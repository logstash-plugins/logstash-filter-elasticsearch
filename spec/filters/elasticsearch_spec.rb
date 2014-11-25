require "logstash/devutils/rspec/spec_helper"
require "ftw"
require "logstash/plugin"
require "logstash/json"

describe "filters/elasticsearch" do
  it "should register" do
    output = LogStash::Plugin.lookup("filter", "elasticsearch").new("query" => "foo", "index" => "bar", "type" => "baz" "sort" "@timestamp:desc")
  end

  # describe "send messages to ElasticSearch using HTTPS", :elasticsearch_secure => true do
  #   subject do
  #     require "logstash/outputs/elasticsearch"
  #     settings = {
  #       "protocol" => "http",
  #       "node_name" => "logstash",
  #       "cluster" => "elasticsearch",
  #       "host" => "node01",
  #       "user" => "user",
  #       "password" => "changeme",
  #       "ssl" => true,
  #       "cacert" => "/tmp/ca/certs/cacert.pem",
  #       # or
  #       #"truststore" => "/tmp/ca/truststore.jks",
  #       #"truststore_password" => "testeteste"
  #     }
  #     next LogStash::Outputs::ElasticSearch.new(settings)
  #   end

  #   before :each do
  #     subject.register
  #   end

  #   it "sends events to ES" do
  #     expect {
  #       subject.receive(LogStash::Event.new("message" => "sample message here"))
  #       subject.buffer_flush(:final => true)
  #     }.to_not raise_error
  #   end
  # end

  # describe "connect using HTTP Authentication", :elasticsearch_secure => true do
  #   subject do
  #     require "logstash/outputs/elasticsearch"
  #     settings = {
  #       "protocol" => "http",
  #       "cluster" => "elasticsearch",
  #       "host" => "node01",
  #       "user" => "user",
  #       "password" => "changeme",
  #     }
  #     next LogStash::Outputs::ElasticSearch.new(settings)
  #   end

  #   before :each do
  #     subject.register
  #   end

  #   it "sends events to ES" do
  #     expect {
  #       subject.receive(LogStash::Event.new("message" => "sample message here"))
  #       subject.buffer_flush(:final => true)
  #     }.to_not raise_error
  #   end
  # end
end
