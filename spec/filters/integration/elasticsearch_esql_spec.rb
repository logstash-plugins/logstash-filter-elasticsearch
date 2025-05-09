# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/elasticsearch"
require "elasticsearch"
require_relative "../../../spec/es_helper"

describe LogStash::Filters::Elasticsearch, integration: true do

  SECURE_INTEGRATION = ENV['SECURE_INTEGRATION'].eql? 'true'
  ES_HOSTS = ["http#{SECURE_INTEGRATION ? 's' : nil}://#{ESHelper.get_host_port}"]

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
  let(:config) do
    {
      "hosts" => ES_HOSTS
    }
  end
  let(:event) { LogStash::Event.new({}) }
  let(:es_client) do
    Elasticsearch::Client.new(hosts: ES_HOSTS)
  end

  before(:all) do
    is_ls_with_esql_supported_client = Gem::Version.create(LOGSTASH_VERSION) >= Gem::Version.create(LogStash::Filters::Elasticsearch::LS_ESQL_SUPPORT_VERSION)
    skip "LS version does not have ES client which supports ES|QL" unless is_ls_with_esql_supported_client

    # Skip tests if ES version doesn't support ES||QL
    es_client = SECURE_INTEGRATION ?
                  Elasticsearch::Client.new(hosts: ES_HOSTS, user: 'tests', password: 'Tests123') :
                  Elasticsearch::Client.new(hosts: ES_HOSTS)
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
        expect(event.get("[@metadata][total_hits]")).to eq(expected_count)
        fields&.each do | old_key, new_key |
          expect(event.get(new_key)).not_to be(nil)
        end
      end
    end

    describe "LIMIT 1 by default" do
      let(:config) do
        super().merge("query" => "FROM #{es_index}")
      end

      include_examples "ESQL query execution", 1
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
      fields = {"message" => "target_message", "count" => "target_count"}
      let(:config) do
        super().merge("query" => "FROM #{es_index} | WHERE type==\"b\" | LIMIT 99", "fields" => fields)
      end

      include_examples "ESQL query execution", 2, fields
    end

    describe "when non-exist field value appear" do
      let(:config) do
        super().merge("query" => "FROM #{es_index} | LIMIT 99", "fields" => {"message" => "target_message", "count" => "target_count"})
      end

      it "processes the event" do
        plugin.filter(event)
        expect(event.get("[@metadata][total_hits]")).to eq(6)
        expect(event.get("target_message").size).to eq(6)
        expect(event.get("target_count").size).to eq(5)
      end
    end
  end
end