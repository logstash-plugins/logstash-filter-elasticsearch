# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin"
require "logstash/filters/elasticsearch"
require_relative "../../../spec/es_helper"

describe LogStash::Filters::Elasticsearch, :integration => true do

  ELASTIC_SECURITY_ENABLED = ENV['ELASTIC_SECURITY_ENABLED'].eql? 'true'
  SECURE_INTEGRATION = ENV['SECURE_INTEGRATION'].eql? 'true'

  let(:base_config) do
    {
        "index" => 'logs',
        "hosts" => ["http#{SECURE_INTEGRATION ? 's' : nil}://#{ESHelper.get_host_port}"],
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
    es_url = ESHelper.get_host_port
    es_url = SECURE_INTEGRATION ? "https://#{es_url}" : "http://#{es_url}"
    args = ELASTIC_SECURITY_ENABLED ? "-u #{credentials['user']}:#{credentials['password']}" : ''
    # Clean ES of data before we start.
    # Delete all templates first.
    ESHelper.curl_and_get_json_response "#{es_url}/_index_template/*", method: 'DELETE', args: args
    # This can fail if there are no indexes, ignore failure.
    ESHelper.curl_and_get_json_response "#{es_url}/_index/*", method: 'DELETE', args: args
    json_args = "-H 'Content-Type: application/json' -d '{\"response\": 404, \"this\":\"that\"}'"
    10.times do
      ESHelper.curl_and_get_json_response "#{es_url}/logs/_doc", method: 'POST', args: args + json_args
    end
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

    it "fails to register plugin" do
      expect { plugin.register }.to raise_error Elasticsearch::Transport::Transport::Errors::Unauthorized
    end

  end if ELASTIC_SECURITY_ENABLED

end
