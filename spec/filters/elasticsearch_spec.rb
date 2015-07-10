# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin"

describe "filter/elasticsearch" do

  it "should register" do
    plugin = LogStash::Plugin.lookup("filter", "elasticsearch").new({})
    expect {plugin.register}.to_not raise_error
  end
end
