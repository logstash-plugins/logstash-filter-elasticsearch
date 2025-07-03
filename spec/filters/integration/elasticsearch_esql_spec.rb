# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/elasticsearch"
require "elasticsearch"
require_relative "../../../spec/es_helper"

describe LogStash::Filters::Elasticsearch, integration: true do

  ELASTIC_SECURITY_ENABLED = ENV['ELASTIC_SECURITY_ENABLED'].eql? 'true'
  SECURE_INTEGRATION = ENV['SECURE_INTEGRATION'].eql? 'true'
  ES_HOSTS = ["http#{SECURE_INTEGRATION ? 's' : nil}://#{ESHelper.get_host_port}"]
  CA_PATH = File.expand_path('../fixtures/test_certs/ca.crt', File.dirname(__FILE__))

  let(:plugin) { described_class.new(config) }
  let(:es_index) { "es-filter-plugin-esql-integration-#{rand(1000)}" }
  let(:test_documents) do
    [
      { "message" => "test message 1", "type" => "a", "count" => 1 },
      { "message" => "test message 2", "type" => "a", "count" => 2 },
      { "message" => "test message 3", "type" => "b", "count" => 3 },
      { "message" => "test message 4", "type" => "b", "count" => 4 },
      { "message" => "test message 5", "type" => "c", "count" => 5 },
      { "message" => "odd test message", "type" => "t" }
    ]
  end

  let(:base_config) do
    {
      "query_type" => "esql",
      "hosts" => ES_HOSTS,
      "ssl_enabled" => SECURE_INTEGRATION
    }
  end

  let(:credentials) do
    if SECURE_INTEGRATION
      { 'user' => 'tests', 'password' => 'Tests123' }
    else
      { 'user' => 'elastic', 'password' => ENV['ELASTIC_PASSWORD'] }
    end
  end

  let(:config) do
    config = ELASTIC_SECURITY_ENABLED ? base_config.merge(credentials) : base_config
    config = { 'ssl_certificate_authorities' => CA_PATH }.merge(config) if SECURE_INTEGRATION
    config
  end

  let(:event) { LogStash::Event.new({}) }

  def es_client
    @es_client ||= begin
      user = SECURE_INTEGRATION ? 'tests' : 'elastic'
      password = SECURE_INTEGRATION ? 'Tests123' : ENV['ELASTIC_PASSWORD']

      es_client_config = { hosts: ES_HOSTS }
      es_client_config = es_client_config.merge({ user: user, password: password }) if ELASTIC_SECURITY_ENABLED || SECURE_INTEGRATION
      es_client_config = es_client_config.merge({ transport_options: { ssl: { ca_path: CA_PATH, verify: false }}}) if SECURE_INTEGRATION

      Elasticsearch::Client.new(es_client_config)
    end
  end

  before(:all) do
    is_ls_with_esql_supported_client = Gem::Version.create(LOGSTASH_VERSION) >= Gem::Version.create(LogStash::Filters::Elasticsearch::LS_ESQL_SUPPORT_VERSION)
    # Skip tests if an ES version doesn't support ES|QL
    skip "LS version does not have ES client which supports ES|QL" unless is_ls_with_esql_supported_client

    es_version_info = es_client.info["version"]
    es_gem_version = Gem::Version.create(es_version_info["number"])
    skip "ES version does not support ES|QL" if es_gem_version.nil? || es_gem_version < Gem::Version.create(LogStash::Filters::Elasticsearch::ES_ESQL_SUPPORT_VERSION)
  end

  before(:each) do
    # Create index with test documents
    es_client.indices.create(index: es_index, body: {}) unless es_client.indices.exists?(index: es_index)

    test_documents.each do |doc|
      es_client.index(index: es_index, body: doc, refresh: true)
    end
  end

  after(:each) do
    es_client.indices.delete(index: es_index) if es_client.indices.exists?(index: es_index)
  end

  describe "run ES|QL queries" do

    before do
      stub_const("LOGSTASH_VERSION", LogStash::Filters::Elasticsearch::LS_ESQL_SUPPORT_VERSION)
    end

    before(:each) do
      plugin.register
    end

    shared_examples "ESQL query execution" do |expected_count, fields|
      it "processes the event" do
        plugin.filter(event)
        expect(event.get("[@metadata][total_values]")).to eq(expected_count)
        fields&.each do | field |
          expect(event.get(field)).not_to be(nil)
        end
      end
    end

    describe "with simple FROM query with LIMIT" do
      let(:config) do
        super().merge("query" => "FROM #{es_index} | LIMIT 99")
      end

      include_examples "ESQL query execution", 6
    end

    describe "with simple FROM and WHERE query combinations" do
      let(:config) do
        super().merge("query" => "FROM #{es_index} | WHERE type==\"b\" | LIMIT 99")
      end

      include_examples "ESQL query execution", 2
    end

    describe "with query params" do
      let(:config) do
        super().merge("query" => "FROM #{es_index} | WHERE type==?type", "query_params" => { "type" => "b" })
      end

      include_examples "ESQL query execution", 2
    end

    describe "when invalid query used" do
      let(:config) do
        super().merge("query" => "FROM undefined index | LIMIT 1")
      end

      it "tags on failure" do
        plugin.filter(event)
        expect(event.to_hash["tags"]).to include("_elasticsearch_lookup_failure")
      end
    end

    describe "when field enrichment requested" do
      let(:config) do
        super().merge("query" => "FROM #{es_index} | WHERE type==\"b\" | LIMIT 99")
      end

      include_examples "ESQL query execution", 2,  %w[message count]
    end

    describe "when non-exist field value appear" do
      let(:config) do
        super().merge("query" => "FROM #{es_index}", "target" => "target_field")
      end

      it "processes the event" do
        plugin.filter(event)
        expect(event.get("[@metadata][total_values]")).to eq(6)
        expect(event.get("target_field").size).to eq(6)
        values = event.get("target_field")
        counts = values.count { |entry| entry.key?("count") }
        messages = values.count { |entry| entry.key?("message") }
        expect(counts).to eq(5)
        expect(messages).to eq(6)
      end
    end
  end
end