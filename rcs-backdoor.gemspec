# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "rcs-backdoor/version"

Gem::Specification.new do |s|
  s.name        = "rcs-backdoor"
  s.version     = RCS::Backdoor::VERSION
  s.authors     = ["alor"]
  s.email       = ["alor@hackingteam.it"]
  s.homepage    = ""
  s.summary     = %q{rcs-backdoor}
  s.description = %q{Simulate a backdoor in ruby}

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_development_dependency "pry"
  s.add_development_dependency "test-unit"
  s.add_development_dependency "colorize"

  s.add_dependency "mail"
  s.add_dependency "log4r", ">= 1.1.9"
  s.add_dependency "rcs-common"
end
