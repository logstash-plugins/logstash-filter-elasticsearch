@files=[]

task :default do
  system("rake -T")
end

require "logstash/devutils/rake"

desc "Generate certificate fixtures used for tests and specs"
task :generate_certificate_fixtures do
  sh "spec/filters/fixtures/generate_test_certs.sh"
end