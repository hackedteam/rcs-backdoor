require "bundler/gem_tasks"

def execute(message)
  print message + '...'
  STDOUT.flush
  if block_given? then
    yield
  end
  puts ' ok'
end

desc "Housekeeping for the project"
task :clean do
  execute "Cleaning the evidence directory" do
    Dir['./evidences/*'].each do |f|
      File.delete(f)
    end
  end
end