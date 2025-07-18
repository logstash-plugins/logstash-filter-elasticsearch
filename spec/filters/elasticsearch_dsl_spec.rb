# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/elasticsearch"

describe LogStash::Filters::Elasticsearch::DslExecutor do
  let(:client) { instance_double(LogStash::Filters::ElasticsearchClient) }
  let(:logger) { double("logger") }
  let(:plugin) { LogStash::Filters::Elasticsearch.new(plugin_config) }
  let(:plugin_config) do
    {
      "index" => "test_index",
      "query" => "test_query",
      "fields" => { "field1" => "field1_mapped" },
      "result_size" => 10,
      "docinfo_fields" => { "_id" => "doc_id" },
      "tag_on_failure" => ["_failure"],
      "enable_sort" => true,
      "sort" => "@timestamp:desc",
      "aggregation_fields" => { "agg1" => "agg1_mapped" }
    }
  end
  let(:dsl_executor) { described_class.new(plugin, logger) }
  let(:event) { LogStash::Event.new({}) }

  describe "#initialize" do
    it "initializes instance variables correctly" do
      expect(dsl_executor.instance_variable_get(:@index)).to eq("test_index")
      expect(dsl_executor.instance_variable_get(:@query)).to eq("test_query")
      expect(dsl_executor.instance_variable_get(:@query_dsl)).to eq(nil)
      expect(dsl_executor.instance_variable_get(:@fields)).to eq({ "field1" => "field1_mapped" })
      expect(dsl_executor.instance_variable_get(:@result_size)).to eq(10)
      expect(dsl_executor.instance_variable_get(:@docinfo_fields)).to eq({ "_id" => "doc_id" })
      expect(dsl_executor.instance_variable_get(:@tag_on_failure)).to eq(["_failure"])
      expect(dsl_executor.instance_variable_get(:@enable_sort)).to eq(true)
      expect(dsl_executor.instance_variable_get(:@sort)).to eq("@timestamp:desc")
      expect(dsl_executor.instance_variable_get(:@aggregation_fields)).to eq({ "agg1" => "agg1_mapped" })
      expect(dsl_executor.instance_variable_get(:@logger)).to eq(logger)
      expect(dsl_executor.instance_variable_get(:@event_decorator)).not_to be_nil
    end
  end

  describe "data fetch" do
    let(:plugin_config) do
      {
        "hosts" => ["localhost:9200"],
        "query" => "response: 404",
        "fields" => { "response" => "code" },
        "docinfo_fields" => { "_index" => "es_index" },
        "aggregation_fields" => { "bytes_avg" => "bytes_avg_ls_field" }
      }
    end

    let(:response) do
      LogStash::Json.load(File.read(File.join(File.dirname(__FILE__), "fixtures", "request_x_1.json")))
    end

    let(:client) { double(:client) }

    before(:each) do
      allow(LogStash::Filters::ElasticsearchClient).to receive(:new).and_return(client)
      if defined?(Elastic::Transport)
        allow(client).to receive(:es_transport_client_type).and_return('elastic_transport')
      else
        allow(client).to receive(:es_transport_client_type).and_return('elasticsearch_transport')
      end
      allow(client).to receive(:search).and_return(response)
      allow(plugin).to receive(:test_connection!)
      allow(plugin).to receive(:setup_serverless)
      plugin.register
    end

    after(:each) do
      Thread.current[:filter_elasticsearch_client] = nil
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

      let(:plugin_config) do
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

      let(:plugin_config) do
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

    context 'when Elasticsearch 7.x gives us a totals object instead of an integer' do
      let(:plugin_config) do
        {
          "hosts" => ["localhost:9200"],
          "query" => "response: 404",
          "fields" => { "response" => "code" },
          "result_size" => 10
        }
      end

      let(:response) do
        LogStash::Json.load(File.read(File.join(File.dirname(__FILE__), "fixtures", "elasticsearch_7.x_hits_total_as_object.json")))
      end

      it "should enhance the current event with new data" do
        plugin.filter(event)
        expect(event.get("[@metadata][total_hits]")).to eq(13476)
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
      let(:plugin_config) do
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
      let(:plugin_config) do
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
        expect(event.get("tags")).to include("tagged")
        expect(event.get("bytes_avg_ls_field")["value"]).to eq(294)
      end
    end

    # Tagging test for negative results
    context "Tagging should not occur if query has no results" do
      let(:plugin_config) do
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
      let(:plugin_config) do
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
      let(:plugin_config) do
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

    context 'with client-level retries' do
      let(:plugin_config) do
        super().merge(
          "retry_on_failure" => 3,
          "retry_on_status" => [500]
        )
      end
    end

    context "with custom headers" do
      let(:plugin_config) do
        {
          "query" => "*",
          "custom_headers" => { "Custom-Header-1" => "Custom Value 1", "Custom-Header-2" => "Custom Value 2" }
        }
      end

      let(:plugin) { LogStash::Filters::Elasticsearch.new(plugin_config) }
      let(:client_double) { double("client") }
      let(:transport_double) { double("transport", options: { transport_options: { headers: plugin_config["custom_headers"] } }) }

      before do
        allow(plugin).to receive(:get_client).and_return(client_double)
        if defined?(Elastic::Transport)
          allow(client_double).to receive(:es_transport_client_type).and_return('elastic_transport')
        else
          allow(client_double).to receive(:es_transport_client_type).and_return('elasticsearch_transport')
        end
        allow(client_double).to receive(:client).and_return(transport_double)
      end

      it "sets custom headers" do
        plugin.register
        client = plugin.send(:get_client).client
        expect(client.options[:transport_options][:headers]).to match(hash_including(plugin_config["custom_headers"]))
      end
    end

    context "if query is on nested field" do
      let(:plugin_config) do
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

  describe "#set_to_event_target" do
    it 'is ready to set to `target`' do
      expect(dsl_executor.apply_target("path")).to eq("path")
    end

    context "when `@target` is nil, default behavior" do
      it "sets the value directly to the top-level event field" do
        dsl_executor.send(:set_to_event_target, event, "new_field", %w[value1 value2])
        expect(event.get("new_field")).to eq(%w[value1 value2])
      end
    end

    context "when @target is defined" do
      let(:plugin_config) {
        super().merge({ "target" => "nested" })
      }

      it "creates a nested structure under the target field" do
        dsl_executor.send(:set_to_event_target, event, "new_field", %w[value1 value2])
        expect(event.get("nested")).to eq({ "new_field" => %w[value1 value2] })
      end

      it "overwrites existing target field with new data" do
        event.set("nested", { "existing_field" => "existing_value", "new_field" => "value0" })
        dsl_executor.send(:set_to_event_target, event, "new_field", ["value1"])
        expect(event.get("nested")).to eq({ "existing_field" => "existing_value", "new_field" => ["value1"] })
      end
    end
  end

end
