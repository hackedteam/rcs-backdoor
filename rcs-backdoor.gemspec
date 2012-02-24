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

  # specify any dependencies here; for example:
  # s.add_development_dependency "rspec"
  # s.add_runtime_dependency "rest-client"
end
