# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin"
require "logstash/filters/elasticsearch"
require_relative "../../../spec/es_helper"

describe LogStash::Filters::Elasticsearch, :integration => true do


  let(:config) do
    {
      "index" => 'logs',
      "hosts" => [ESHelper.get_host_port],
      "query" => "response: 404",
      "sort" => "response",
      "fields" => [ ["response", "code"] ],
    }
  end
  let(:plugin) { described_class.new(config) }
  let(:event)  { LogStash::Event.new({}) }

  before(:each) do
    @es = ESHelper.get_client
    # Delete all templates first.
    # Clean ES of data before we start.
    @es.indices.delete_template(:name => "*")
    # This can fail if there are no indexes, ignore failure.
    @es.indices.delete(:index => "*") rescue nil
    10.times do
      ESHelper.index_doc(@es, :index => 'logs', :body => { :response => 404, :this => 'that'})
    end
    @es.indices.refresh

    plugin.register
  end

  it "should enhance the current event with new data" do
    plugin.filter(event)
    expect(event.get('code')).to eq(404)
  end

  context "when retrieving a list of elements" do

    let(:config) do
      {
        "index" => 'logs',
        "hosts" => [ESHelper.get_host_port],
        "query" => "response: 404",
        "fields" => [ ["response", "code"] ],
        "sort" => "response",
        "result_size" => 10
      }
    end

    it "should enhance the current event with new data" do
      plugin.filter(event)
      expect(event.get("code")).to eq([404]*10)
    end

  end
end
