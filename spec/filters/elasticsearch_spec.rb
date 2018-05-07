# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin"
require "logstash/filters/elasticsearch"
require "logstash/json"

describe LogStash::Filters::Elasticsearch do

  context "registration" do

    let(:plugin) { LogStash::Plugin.lookup("filter", "elasticsearch").new({}) }

    it "should not raise an exception" do
      expect {plugin.register}.to_not raise_error
    end
  end

  describe "data fetch" do
    let(:config) do
      {
        "hosts" => ["localhost:9200"],
        "query" => "response: 404",
        "fields" => { "response" => "code" },
        "docinfo_fields" => { "_index" => "es_index" },
        "aggregation_fields" => { "bytes_avg" => "bytes_avg_ls_field" }
      }
    end
    let(:plugin) { described_class.new(config) }
    let(:event)  { LogStash::Event.new({}) }

    let(:response) do
      LogStash::Json.load(File.read(File.join(File.dirname(__FILE__), "fixtures", "request_x_1.json")))
    end

    let(:client) { double(:client) }

    before(:each) do
      allow(LogStash::Filters::ElasticsearchClient).to receive(:new).and_return(client)
      allow(client).to receive(:search).and_return(response)
      plugin.register
    end

    after(:each) do
      Thread.current[:filter_elasticsearch_client] = nil
    end

    # Since the Elasticsearch Ruby client is not thread safe
    # and under high load we can get error with the connection pool
    # we have decided to create a new instance per worker thread which
    # will be lazy created on the first call to `#filter`
    #
    # I am adding a simple test case for future changes
    it "uses a different connection object per thread wait" do
      expect(plugin.clients_pool.size).to eq(0)

      Thread.new { plugin.filter(event) }.join
      Thread.new { plugin.filter(event) }.join

      expect(plugin.clients_pool.size).to eq(2)
    end

    it "should enhance the current event with new data" do
      plugin.filter(event)
      expect(event.get("code")).to eq(404)
      expect(event.get("es_index")).to eq("logstash-2014.08.26")
      expect(event.get("bytes_avg_ls_field")["value"]).to eq(294)
    end

    it "should receive all necessary params to perform the search" do
      expect(client).to receive(:search).with({:q=>"response: 404", :size=>1, :index=>"", :sort=>"@timestamp:desc"})
      plugin.filter(event)
    end

    context "when asking to hit specific index" do

      let(:config) do
        {
          "index" => "foo*",
          "hosts" => ["localhost:9200"],
          "query" => "response: 404",
          "fields" => { "response" => "code" }
        }
      end

      it "should receive all necessary params to perform the search" do
        expect(client).to receive(:search).with({:q=>"response: 404", :size=>1, :index=>"foo*", :sort=>"@timestamp:desc"})
        plugin.filter(event)
      end
    end

    context "when asking for more than one result" do

      let(:config) do
        {
          "hosts" => ["localhost:9200"],
          "query" => "response: 404",
          "fields" => { "response" => "code" },
          "result_size" => 10
        }
      end

      let(:response) do
        LogStash::Json.load(File.read(File.join(File.dirname(__FILE__), "fixtures", "request_x_10.json")))
      end

      it "should enhance the current event with new data" do
        plugin.filter(event)
        expect(event.get("code")).to eq([404]*10)
      end
    end

    context "if something wrong happen during connection" do

      before(:each) do
        allow(LogStash::Filters::ElasticsearchClient).to receive(:new).and_return(client)
        allow(client).to receive(:search).and_raise("connection exception")
        plugin.register
      end

      it "tag the event as something happened, but still deliver it" do
        expect(plugin.logger).to receive(:warn)
        plugin.filter(event)
        expect(event.to_hash["tags"]).to include("_elasticsearch_lookup_failure")
      end
    end

    # Tagging test for positive results
    context "Tagging should occur if query returns results" do
      let(:config) do
        {
          "index" => "foo*",
          "hosts" => ["localhost:9200"],
          "query" => "response: 404",
          "add_tag" => ["tagged"]
        }
      end

      let(:response) do
        LogStash::Json.load(File.read(File.join(File.dirname(__FILE__), "fixtures", "request_x_10.json")))
      end

      it "should tag the current event if results returned" do
        plugin.filter(event)
        expect(event.to_hash["tags"]).to include("tagged")
      end
    end

    context "an aggregation search with size 0 that matches" do
      let(:config) do
        {
          "index" => "foo*",
          "hosts" => ["localhost:9200"],
          "query" => "response: 404",
          "add_tag" => ["tagged"],
          "result_size" => 0,
          "aggregation_fields" => { "bytes_avg" => "bytes_avg_ls_field" }
        }
      end

      let(:response) do
        LogStash::Json.load(File.read(File.join(File.dirname(__FILE__), "fixtures", "request_size0_agg.json")))
      end

      it "should tag the current event" do
        plugin.filter(event)
        puts event.to_hash
        expect(event.get("tags")).to include("tagged")
        expect(event.get("bytes_avg_ls_field")["value"]).to eq(294)
      end
    end

    # Tagging test for negative results
    context "Tagging should not occur if query has no results" do
      let(:config) do
        {
          "index" => "foo*",
          "hosts" => ["localhost:9200"],
          "query" => "response: 404",
          "add_tag" => ["tagged"]
        }
      end

      let(:response) do
        LogStash::Json.load(File.read(File.join(File.dirname(__FILE__), "fixtures", "request_error.json")))
      end

      it "should not tag the current event" do
        plugin.filter(event)
        expect(event.to_hash["tags"]).to_not include("tagged")
      end
    end
    context "testing a simple query template" do
      let(:config) do
        {
          "hosts" => ["localhost:9200"],
          "query_template" => File.join(File.dirname(__FILE__), "fixtures", "query_template.json"),
          "fields" => { "response" => "code" },
          "result_size" => 1
        }
      end

      let(:response) do
        LogStash::Json.load(File.read(File.join(File.dirname(__FILE__), "fixtures", "request_x_1.json")))
      end

      it "should enhance the current event with new data" do
        plugin.filter(event)
        expect(event.get("code")).to eq(404)
      end

    end

    context "testing a simple index substitution" do
      let(:event) {
        LogStash::Event.new(
            {
                "subst_field" => "subst_value"
            }
        )
      }
      let(:config) do
        {
            "index" => "foo_%{subst_field}*",
            "hosts" => ["localhost:9200"],
            "query" => "response: 404",
            "fields" => { "response" => "code" }
        }
      end

      it "should receive substituted index name" do
        expect(client).to receive(:search).with({:q => "response: 404", :size => 1, :index => "foo_subst_value*", :sort => "@timestamp:desc"})
        plugin.filter(event)
      end
    end

    context "if query result errored but no exception is thrown" do
      let(:response) do
        LogStash::Json.load(File.read(File.join(File.dirname(__FILE__), "fixtures", "request_error.json")))
      end

      before(:each) do
        allow(LogStash::Filters::ElasticsearchClient).to receive(:new).and_return(client)
        allow(client).to receive(:search).and_return(response)
        plugin.register
      end

      it "tag the event as something happened, but still deliver it" do
        expect(plugin.logger).to receive(:warn)
        plugin.filter(event)
        expect(event.to_hash["tags"]).to include("_elasticsearch_lookup_failure")
      end
    end

    context "if query is on nested field" do
      let(:config) do
        {
            "hosts" => ["localhost:9200"],
            "query" => "response: 404",
            "fields" => [ ["[geoip][ip]", "ip_address"] ]
        }
      end

      it "should enhance the current event with new data" do
        plugin.filter(event)
        expect(event.get("ip_address")).to eq("66.249.73.185")
      end

    end

  end

end
