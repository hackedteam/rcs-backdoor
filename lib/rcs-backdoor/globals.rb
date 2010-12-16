
module RCS
module Backdoor

module Globals

  SYNC_HOST     = "192.168.100.100"

  BACKDOOR_ID   = "RCS_0000000001"
  INSTANCE_ID   = ["47170C3E047B6A910E7ECC2E987060DB2FF06CD8"]
  BACKDOOR_TYPE = "WIN32"
  CONF_KEY      = "-HcIbnSmrnaXFk6peeZJMx8HFcJPg9Hx"
  SIGNATURE     = "4yeN5zu0+il3Jtcb5a1sBcAdjYFcsD9z"

  VERSION       = 2010111401
  USERID        = "ALoR"
  DEVICEID      = "The One"
  SOURCEID      = "192.168.1.175"
  
end

end # Backdoor::
end # RCS::


if __FILE__ == $0
  require 'yaml'

  config = {'SYNC_HOST' => "192.168.1.169"}

  binary = {'BACKDOOR_ID'   => "RCS_0000000001",
            'INSTANCE_ID'   => ["47170C3E047B6A910E7ECC2E987060DB2FF06CD8"],
            'BACKDOOR_TYPE' => "WIN32",
            'CONF_KEY'      => "-HcIbnSmrnaXFk6peeZJMx8HFcJPg9Hx",
            'SIGNATURE'     => "4yeN5zu0+il3Jtcb5a1sBcAdjYFcsD9z"
           }

  ident = {'VERSION'  => 2010111401,
           'USERID'   => "ALoR",
           'DEVICEID' => "The One",
           'SOURCEID' => "192.168.1.175"
          }

  # Write the yaml description to a file
  File.open("binary.yaml", 'w') do |f|
    f.write(binary.to_yaml)
  end

  File.open("ident.yaml", 'w') do |f|
    f.write(ident.to_yaml)
  end

  File.open("config.yaml", 'w') do |f|
    f.write(config.to_yaml)
  end
end
