# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin"
require "logstash/filters/elasticsearch"

describe LogStash::Filters::Elasticsearch, :integration => true do

  let(:config) do
    {
      "hosts" => ["localhost:9200"],
      "query" => "response: 404",
      "fields" => [ ["response", "code"] ],
    }
  end
  let(:plugin) { described_class.new(config) }
  let(:event)  { LogStash::Event.new({}) }

  before(:each) do
    plugin.register
  end

  it "should enhance the current event with new data" do
    plugin.filter(event)
    expect(event["code"]).to eq(404)
  end

  context "when retrieving a list of elements" do

    let(:config) do
      {
        "hosts" => ["localhost:9200"],
        "query" => "response: 404",
        "fields" => [ ["response", "code"] ],
        "result_size" => 10
      }
    end

    it "should enhance the current event with new data" do
      plugin.filter(event)
      expect(event["code"]).to eq([404]*10)
    end

  end
end
