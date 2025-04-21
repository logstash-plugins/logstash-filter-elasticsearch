# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/elasticsearch"

describe LogStash::Filters::Elasticsearch::EsqlExecutor do
  let(:client) { instance_double(LogStash::Filters::ElasticsearchClient) }
  let(:logger) { double("logger") }
  let(:plugin) { LogStash::Filters::Elasticsearch.new(plugin_config) }
  let(:plugin_config) do
    {
      "query_mode" => "esql",
      "query" => "FROM test-index | STATS count() BY field"
    }
  end
  let(:esql_executor) { described_class.new(plugin, logger) }

  describe "when initializes" do
    it "sets up the ESQL client with correct parameters" do
      expect(esql_executor.instance_variable_get(:@query)).to eq(plugin_config["query"])
      expect(esql_executor.instance_variable_get(:@esql_params)).to eq([])
      expect(esql_executor.instance_variable_get(:@fields)).to eq({})
      expect(esql_executor.instance_variable_get(:@tag_on_failure)).to eq(["_elasticsearch_lookup_failure"])
    end
  end

  describe "when processes" do
    let(:plugin_config) {
      super()
        .merge(
          {
            "query" => "FROM my-index | WHERE field = ?foo",
            "esql_params" => [{ "foo" => "%{bar}" }],
            "fields" => { "val" => "val_new" }
          })
    }
    let(:event) { LogStash::Event.new({}) }
    let(:response) { { 'values' => [%w[foo bar]], 'columns' => [{ 'name' => 'id' }, { 'name' => 'val' }] } }

    before do
      allow(event).to receive(:sprintf).and_return("resolved_value")
    end

    it "resolves parameters" do
      expect(event).to receive(:sprintf).with("%{bar}").and_return("resolved_value")
      resolved_params = esql_executor.send(:resolve_parameters, event)
      expect(resolved_params).to include("foo" => "resolved_value")
    end

    it "executes the query with resolved parameters" do
      allow(logger).to receive(:debug)
      expect(client).to receive(:search).with(
        { body: { query: plugin_config["query"], params: [{ "foo" => "resolved_value" }] }, format: 'json' },
        'esql')
      resolved_params = esql_executor.send(:resolve_parameters, event)
      esql_executor.send(:execute_query, client, resolved_params)
    end

    it "informs warning if received warning" do
      allow(response).to receive(:headers).and_return({ "warning" => "some warning" })
      expect(logger).to receive(:warn).with("ES|QL executor received warning", { :message => "some warning" })
      esql_executor.send(:inform_warning, response)
    end

    it "processes the response and adds metadata" do
      expect(event).to receive(:set).with("[@metadata][total_hits]", 1)
      expect(event).to receive(:set).with("val_new", "bar")
      esql_executor.send(:process_response, event, response)
    end

    it "executes chain of processes" do
      allow(plugin).to receive(:decorate)
      allow(logger).to receive(:debug)
      allow(response).to receive(:headers).and_return({})
      expect(client).to receive(:search).with(
        {
          body: { query: plugin_config["query"], params: plugin_config["esql_params"] },
          format: 'json'
        },
        'esql'
      ).and_return(response)
      expect { esql_executor.process(client, LogStash::Event.new({ "hello" => "world" })) }.to_not raise_error
    end

    it "tags on plugin failures" do
      expect(event).to receive(:sprintf).with("%{bar}").and_raise("Event#sprintf error")

      expect(logger).to receive(:error).with("Failed to resolve parameter", {:error=>"Event#sprintf error", :key=>"foo", :value=>"%{bar}"})
      expect(logger).to receive(:error).with("Failed to process ES|QL filter", exception: instance_of(RuntimeError))
      expect(event).to receive(:tag).with("_elasticsearch_lookup_failure")
      esql_executor.process(client, event)
    end

    it "tags on query execution failures" do
      allow(logger).to receive(:debug)
      allow(client).to receive(:search).and_raise("Query execution error")

      expect(logger).to receive(:error).with("Failed to process ES|QL filter", exception: instance_of(RuntimeError))
      expect(event).to receive(:tag).with("_elasticsearch_lookup_failure")
      esql_executor.process(client, event)
    end
  end

end if LOGSTASH_VERSION >= LogStash::Filters::Elasticsearch::LS_ESQL_SUPPORT_VERSION