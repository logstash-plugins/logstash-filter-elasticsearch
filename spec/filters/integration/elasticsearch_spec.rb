# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin"
require "logstash/filters/elasticsearch"
require_relative "../../../spec/es_helper"

describe LogStash::Filters::Elasticsearch, :integration => true do

  ELASTIC_SECURITY_ENABLED = ENV['ELASTIC_SECURITY_ENABLED'].eql? 'true'

  let(:base_config) do
    {
        "index" => 'logs',
        "hosts" => [ESHelper.get_host_port],
        "query" => "response: 404",
        "sort" => "response",
        "fields" => [ ["response", "code"] ],
    }
  end

  let(:credentials) do
    { 'user' => 'elastic', 'password' => ENV['ELASTIC_PASSWORD'] }
  end

  let(:config) do
    ELASTIC_SECURITY_ENABLED ? base_config.merge(credentials) : base_config
  end

  let(:plugin) { described_class.new(config) }
  let(:event)  { LogStash::Event.new({}) }

  before(:each) do
    @es = ESHelper.get_client(ELASTIC_SECURITY_ENABLED ? credentials : {})
    # Delete all templates first.
    # Clean ES of data before we start.
    @es.indices.delete_template(:name => "*")
    # This can fail if there are no indexes, ignore failure.
    @es.indices.delete(:index => "*") rescue nil
    10.times do
      ESHelper.index_doc(@es, :index => 'logs', :body => { :response => 404, :this => 'that'})
    end
    @es.indices.refresh
  end

  it "should enhance the current event with new data" do
    plugin.register
    plugin.filter(event)
    expect(event.get('code')).to eq(404)
  end

  context "when retrieving a list of elements" do

    let(:config) do
      super().merge("fields" => [ ["response", "code"] ], "result_size" => 10)
    end

    before { plugin.register }

    it "should enhance the current event with new data" do
      plugin.filter(event)
      expect(event.get("code")).to eq([404]*10)
    end

  end

  context "incorrect auth credentials" do

    let(:config) do
      super().reject { |key, _| key == 'password' }
    end

    it "should fail with 401" do
      expect { plugin.register }.to raise_error Elasticsearch::Transport::Transport::Errors::Unauthorized
    end

  end if ELASTIC_SECURITY_ENABLED

end
