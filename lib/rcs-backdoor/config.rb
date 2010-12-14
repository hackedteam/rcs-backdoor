#
# Configuration parser
#

# RCS::Common
require 'rcs-common/trace'
require 'rcs-common/crypt'

module RCS
  
class Config
  include Crypt
  @content = ""
  
  def initialize(backdoor, buff)
    @backdoor = backdoor
    # TODO: remove this when the new config format will land on earth :)
    # skip the first 8 bytes (the delta date)
    @content = buff[8..-1] 
    trace :info, "Configuration size is #{@content.length}"
  end
  
  def dump_to_file
    
    # dump the configuration still encrypted
    str = './' + @backdoor.id + "_config.enc"
    f = File.new(str, File::CREAT | File::TRUNC | File::RDWR, 0644)
    f.write @content
    f.close
    trace :debug, str + " created."
    
    # dump the configuration in clear
    str = './' + @backdoor.id + "_config.dec"
    f = File.new(str, File::CREAT | File::TRUNC | File::RDWR, 0644)
    f.write aes_decrypt(@content, @backdoor.conf_key, PAD_NOPAD)
    f.close
    trace :debug, str + " created."
    
  end
  
end

end # RCS::

if __FILE__ == $0
  # TODO Generated stub
end