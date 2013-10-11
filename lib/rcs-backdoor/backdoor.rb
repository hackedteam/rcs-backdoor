#
#  The main file of the backdoor
#

# relatives
require_relative 'sync.rb'
require_relative 'protocol.rb'

# from RCS::Common
require 'rcs-common/trace'
require 'rcs-common/crypt'
require 'rcs-common/evidence'

# from System
require 'digest/md5'
require 'digest/sha1'
require 'ostruct'
require 'yaml'
require 'optparse'
require 'fileutils'

module RCS
module Backdoor
#
# This is the Backdoor object
# it needs the backdoor_id, instance and conf_key to be created
# all those parameters need to be passed as string taken from the db
#

class Backdoor
  include Tracer
  
  attr_reader :id
  attr_reader :instance
  attr_reader :type
  attr_reader :conf_key
  attr_reader :evidence_key
  attr_reader :signature
  attr_reader :version
  
  attr_reader :userid
  attr_reader :deviceid
  attr_reader :sourceid
  
  attr_reader :evidences

  attr_accessor :scout
  
  #setup all the backdoor parameters
  def initialize(binary_file, ident_file, options = {})
    @options = options

    # parse the parameters from the binary patched constants
    trace :debug, "Parsing binary data..."
    binary = load_yaml(binary_file)

    # instantiate le empty log queue
    @evidences = []
    
    # plain string 'RCS_000000000x'
    @id = binary['BACKDOOR_ID']
    
    # the subtype of the backdoor (eg: WIN32, BLACKBERRY...)
    @type = binary['BACKDOOR_TYPE']
    
    # the conf key is passed as a string taken from the db
    # we need to calculate the MD5 and use it in binary form
    @conf_key = Digest::MD5.digest binary['CONF_KEY']
    
    # the log key is passed as a string taken from the db
    # we need to calculate the MD5 and use it in binary form
    @evidence_key = Digest::MD5.digest binary['EVIDENCE_KEY']
    
    # the backdoor signature is passed as a string taken from the db
    # we need to calculate the MD5 and use it in binary form
    @signature = Digest::MD5.digest binary['SIGNATURE']
    
    # the backdoor version
    @version = binary['VERSION']
    
    ident = load_yaml(ident_file)
    ident['INSTANCE_ID'] = ident['INSTANCE_ID'][0..-((@options[:tag].size)+2)]+"_"+@options[:tag] if @options[:tag]
    # the instance is passed as a string taken from the db
    # we need to convert to binary
    @instance = [ident['INSTANCE_ID']].pack('H*')

    # directory where evidence files are be stored
    @evidence_dir = File.join(Dir.pwd, 'evidence', ident['INSTANCE_ID'])
    
    @userid = ident['USERID'] || ''
    @deviceid = ident['DEVICEID'] || ''
    @sourceid = ident['SOURCEID'] || ''

    @info = { :device_id => @deviceid, :user_id => @userid, :source_id => @sourceid }

    trace :debug, "Backdoor instantiated: " << @id << @instance.unpack('H*').to_s
    trace :debug, "Backdoor ident: [#{@userid}] [#{@deviceid}] [#{@sourceid}]"

    @scout = false

    begin
      # instantiate the sync object with the protocol to be used
      # and a reference to the backdoor
      @sync = Sync.new(:REST, self)
    rescue Exception => detail
      trace :fatal, "ERROR: " << detail.to_s
      raise
    end
  end

  def load_yaml(path)
    File.open(path, "r") do |f|
      hash = YAML.load(f.read)
      is_single_config = hash.keys.include?("INSTANCE_ID")
      return hash if is_single_config
      config_name = @options[:config_name] || "default"
      hash[config_name] || raise("Unable to find configuration #{config_name.inspect} in file #{File.basename(path)}")
      return hash[config_name]
    end
  rescue Exception => ex
    trace :fatal, "Cannot load yaml file #{File.basename(path)}: #{ex.message}"
    exit(1)
  end

  # perform the synchronization with the server
  def sync(host, delete_evidence = true)
    trace :debug, "Loading evidences in memory ..."
    # retrieve the evidence from the local dir
    Dir["#{@evidence_dir}/*"].each do |f|
      @evidences << Evidence.new(@evidence_key).load_from_file(f)
    end

    trace :debug, "Synchronizing ..."
    # perform the sync
    @sync.perform host

    if delete_evidence
      trace :debug, "Deleting evidences ..."
      # delete all evidence sent
      Dir["#{@evidence_dir}/*"].each do |f|
        File.delete(f)
      end
    end

  end
  
  # create some evidences
  def create_evidences(num, type = :RANDOM)
    # ensure the directory is created

    FileUtils.rm_rf(@evidence_dir)

    FileUtils.mkpath(@evidence_dir) if not File.directory?(@evidence_dir)
    
    real_type = type
    
    # generate the evidence
    num.times do
      #real_type = RCS::EVIDENCE_TYPES.values.sample if type == :RANDOM
      real_type = [:APPLICATION, :DEVICE, :CHAT, :CLIPBOARD, :CAMERA, :INFO, :KEYLOG, :SCREENSHOT, :MOUSE, :FILEOPEN, :FILECAP].sample if type == :RANDOM
      Evidence.new(@evidence_key).generate(real_type, @info).dump_to_file(@evidence_dir)
    end
  end
end

# this module is used only form bin/rcs-backdoor as a wrapper to
# execute the backdoor from command line
class Application
  include RCS::Tracer

  def run_backdoor(path_to_binary, path_to_ident, options)
    b = RCS::Backdoor::Backdoor.new(path_to_binary, path_to_ident, options)

    # set the scout flag if specified
    b.scout = true if options[:scout]

    if options[:generate] then
      trace :info, "Creating #{options[:gen_num]} fake evidences..."
      b.create_evidences(options[:gen_num], options[:gen_type])
    end
    
    while true
      if options[:sync] then
        b.sync options[:sync_host], !(options[:randomize] or options[:loop]) # delete evidences if not randomizing
      end
      
      break unless options[:loop]
      
      options[:loop_delay].times do |n|
        sleep 1
        trace :info, "#{options[:loop_delay] - n} seconds to next synchronization." if n % 5 == 0
      end 
    end
  rescue Interrupt
    trace :info, "User asked to exit. Bye bye!"
    return 0
  rescue Exception => e
    trace :fatal, "FAILURE: " << e.to_s
    trace :fatal, "EXCEPTION: " + e.backtrace.join("\n")
    return 1
  end
  
  def run(options)

    # if we can't find the trace config file, default to the system one
    if File.exist?('trace.yaml') then
      load_path = Dir.pwd
      trace_yaml = 'trace.yaml'
    else
      load_path = File.dirname(File.dirname(File.dirname(__FILE__))) + "/bin"
      trace_yaml = load_path + "/trace.yaml"
      puts "Cannot find 'trace.yaml' using the default one (#{trace_yaml})"
    end
    
    # initialize the tracing facility
    begin
      trace_init load_path, trace_yaml
    rescue Exception => e
      puts e
      exit
    end

    unless options[:randomize].nil?
      binary = begin
        File.open(load_path + '/ident.yaml', "r") do |f|
          binary = YAML.load(f.read)
        end
      rescue
        trace :fatal, "Cannot open binary patched file"
        exit
      end

      threads = []
      options[:randomize].times do |n|
        binary["INSTANCE_ID"] = Digest::SHA1.hexdigest(n.to_s).upcase
        path_to_yaml = load_path + "/ident#{n}.yaml"
        File.open(path_to_yaml, "w") {|f| f.write(binary.to_yaml)}
        trace :info, "Spawned backdoor #{path_to_yaml}"
        threads << Thread.new { run_backdoor(load_path + '/binary.yaml', path_to_yaml, options)}
      end

      begin
        threads.each do |th|
          th.join
        end
      rescue Interrupt
        trace :info, "User asked to exit. Bye bye!"
        return 0
      end

    else
      run_backdoor(load_path + '/binary.yaml', load_path + '/ident.yaml', options)
    end

    # concluded successfully
    return 0
  end

  # since we cannot use trace from a class method
  # we instantiate here an object and run it
  def self.run!(*argv)
    # This hash will hold all of the options parsed from the command-line by OptionParser.
    options = {}

    srand(Time.now.to_i)
    
    types = [:RANDOM] + RCS::EVIDENCE_TYPES.values
    
    optparse = OptionParser.new do |opts|
      # Set a banner, displayed at the top of the help screen.
      opts.banner = "Usage: rcs-backdoor [options] arg1 arg2 ..."

      # Define the options, and what they do
      opts.on( '-r', '--randomize NUM', Integer, 'Randomize NUM instances') do |num|
        options[:randomize] = num
      end
      opts.on( '-g', '--generate NUM', Integer, 'Generate NUM evidences' ) do |num|
        options[:generate] = true
        options[:gen_num] = num
      end
      opts.on( '-t', '--type TYPE', types, 'Generate evidences of type TYPE' ) do |type|
        options[:gen_type] = type
      end
      opts.on( '-s', '--sync HOST', 'Synchronize with remote HOST' ) do |host|
        options[:sync] = true
        options[:sync_host] = host
      end
      opts.on('--tag STRING', 'Append to instance string' ) do |tag|
        options[:tag] = tag
      end
      opts.on( '-l', '--loop DELAY', Integer, 'Loop synchronization every DELAY seconds') do |seconds|
        options[:loop] = true
        options[:loop_delay] = seconds
      end
      opts.on( '-c', '--config CONFIGURATION', String, 'Configuration/environment name') do |value|
        options[:config_name] = value
      end
      opts.on( '--scout', 'Auth like a scout' ) do
        options[:scout] = true
      end

      # This displays the help screen, all programs are assumed to have this option.
      opts.on( '-h', '--help', 'Display this screen' ) do
        puts opts
        exit
      end
    end

    optparse.parse(argv)

    return Application.new.run(options)
  end

end # Application::

end # Backdoor::
end # RCS::

if __FILE__ == $0
  RCS::Backdoor::Application.run!(*ARGV)
end
