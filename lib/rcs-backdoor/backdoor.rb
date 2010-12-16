#
#  The main file of the backdoor
#

# relatives
require_relative 'sync.rb'
require_relative 'protocol.rb'

# from RCS::Common
require 'rcs-common/trace'
require 'rcs-common/evidence'

# from System
require 'digest/md5'
require 'ostruct'
require 'yaml'

module RCS
module Backdoor
#
# This is the Backdoor object
# it needs the backdoor_id, instance and conf_key to be created
# all thos parameters need to be passed as string taken from the db
#
class Backdoor
  include Tracer
  
  attr_reader :id
  attr_reader :instance
  attr_reader :type
  attr_reader :conf_key
  attr_reader :signature
  attr_reader :version
  
  attr_reader :userid
  attr_reader :deviceid
  attr_reader :sourceid
  
  attr_reader :logs
  
  #setup all the backdoor parameters
  def initialize(binary_file, ident_file)
    
    # initialize the trace facility with the working directory
    trace_init Dir.pwd

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
    @logs = []
    
    # plain string 'RCS_000000000x'
    @id = binary['BACKDOOR_ID']

    # the subtype of the backdoor (eg: WIN32, BLACKBERRY...)
    @type = binary['BACKDOOR_TYPE']
    
    # the conf key is passed as a string taken from the db
    # we need to calculate the MD5 and use it in binary form
    @conf_key = Digest::MD5.digest binary['CONF_KEY']
  
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

    @userid = ident['USERID']
    @deviceid = ident['DEVICEID']
    @sourceid = ident['SOURCEID']

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
  
  # create some logs
  def create_logs(num)
    num.times do
      @logs << Evidence.new
    end
  end
end

# this module is used only form bin/rcs-backdoor as a wrapper to
# execute the backdoor from command line
class Application
  include RCS::Tracer

  def run(*argv)

    # initialize the tracing facility
    begin
      trace_init Dir.pwd
    rescue Exception => e
      puts e
      exit
    end

    begin
      trace :info, "Creating the backdoor..."
      b = RCS::Backdoor::Backdoor.new 'binary.yaml', 'ident.yaml'

      trace :info, "Creating fake logs..."
      b.create_logs(5)

      trace :info, "Synchronizing..."
      b.sync "192.168.100.100"

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
    return Application.new.run(argv)
  end

end # Application::

end # Backdoor::
end # RCS::

if __FILE__ == $0
  RCS::Backdoor::Application.run!(*ARGV)
end
