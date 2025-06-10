# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/elasticsearch"

describe LogStash::Filters::Elasticsearch::EsqlExecutor do
  let(:client) { instance_double(LogStash::Filters::ElasticsearchClient) }
  let(:logger) { double("logger") }
  let(:plugin) { LogStash::Filters::Elasticsearch.new(plugin_config) }
  let(:plugin_config) do
    {
      "query_type" => "esql",
      "query" => "FROM test-index | STATS count() BY field | LIMIT 10"
    }
  end
  let(:esql_executor) { described_class.new(plugin, logger) }

  context "when initializes" do
    it "sets up the ESQL executor with correct parameters" do
      allow(logger).to receive(:debug)
      allow(logger).to receive(:warn)
      expect(esql_executor.instance_variable_get(:@query)).to eq(plugin_config["query"])
      expect(esql_executor.instance_variable_get(:@referenced_params)).to eq({})
      expect(esql_executor.instance_variable_get(:@static_params)).to eq([])
      expect(esql_executor.instance_variable_get(:@tag_on_failure)).to eq(["_elasticsearch_lookup_failure"])
    end
  end

  context "when processes" do
    let(:plugin_config) {
      super()
        .merge(
          {
            "query" => "FROM my-index | WHERE field = ?foo | LIMIT 5",
            "query_params" => { "foo" => "[bar]" }
          })
    }
    let(:event) { LogStash::Event.new({}) }
    let(:response) {
      {
        'values' => [["foo", "bar", nil]],
        'columns' => [{ 'name' => 'id', 'type' => 'keyword' }, { 'name' => 'val', 'type' => 'keyword' }, { 'name' => 'odd', 'type' => 'keyword' }]
      }
    }

    before do
      allow(logger).to receive(:debug)
      allow(logger).to receive(:warn)
    end

    it "resolves parameters" do
      expect(event).to receive(:get).with("[bar]").and_return("resolved_value")
      resolved_params = esql_executor.send(:resolve_parameters, event)
      expect(resolved_params).to include("foo" => "resolved_value")
    end

    it "executes the query with resolved parameters" do
      allow(logger).to receive(:debug)
      expect(event).to receive(:get).with("[bar]").and_return("resolved_value")
      expect(client).to receive(:esql_query).with(
        { body: { query: plugin_config["query"], params: [{ "foo" => "resolved_value" }] }, format: 'json', drop_null_columns: true, })
      resolved_params = esql_executor.send(:resolve_parameters, event)
      esql_executor.send(:execute_query, client, resolved_params)
    end

    it "informs warning if received warning" do
      allow(response).to receive(:headers).and_return({ "warning" => "some warning" })
      expect(logger).to receive(:warn).with("ES|QL executor received warning", { :message => "some warning" })
      esql_executor.send(:inform_warning, response)
    end

    it "processes the response and adds metadata" do
      expect(event).to receive(:set).with("[@metadata][total_values]", 1)
      # [id], [val] aren't resolved via sprintf, use as it is
      expect(event).to receive(:set).with("[id]", "foo")
      expect(event).to receive(:set).with("[val]", "bar")
      esql_executor.send(:process_response, event, response)
    end

    it "executes chain of processes" do
      allow(plugin).to receive(:decorate)
      allow(logger).to receive(:debug)
      allow(response).to receive(:headers).and_return({})
      expect(client).to receive(:esql_query).with(
        {
          body: { query: plugin_config["query"], params: [{"foo"=>"resolve_me"}] },
          format: 'json',
          drop_null_columns: true,
        }).and_return(response)

      event = LogStash::Event.new({ "hello" => "world", "bar" => "resolve_me" })
      expect { esql_executor.process(client, event) }.to_not raise_error
      expect(event.get("[@metadata][total_values]")).to eq(1)
      expect(event.get("hello")).to eq("world")
      expect(event.get("val")).to eq("bar")
      expect(event.get("odd")).to be_nil # filters out non-exist fields
    end

    it "tags on plugin failures" do
      expect(event).to receive(:get).with("[bar]").and_raise("Event#get Invalid FieldReference error")

      expect(logger).to receive(:error).with("Failed to process ES|QL filter", exception: instance_of(RuntimeError))
      expect(event).to receive(:tag).with("_elasticsearch_lookup_failure")
      esql_executor.process(client, event)
    end

    it "tags on query execution failures" do
      allow(logger).to receive(:debug)
      allow(client).to receive(:esql_query).and_raise("Query execution error")

      expect(logger).to receive(:error).with("Failed to process ES|QL filter", exception: instance_of(RuntimeError))
      expect(event).to receive(:tag).with("_elasticsearch_lookup_failure")
      esql_executor.process(client, event)
    end

    describe "#target" do
      let(:event) { LogStash::Event.new({ "hello" => "world", "bar" => "resolve_me" }) }
      let(:response) {
        super().merge({ 'values' => [["foo", "bar", nil], %w[hello again world], %w[another value here]] })
      }
      before(:each) do
        expect(client).to receive(:esql_query).with(any_args).and_return(response)
        allow(plugin).to receive(:decorate)
        allow(logger).to receive(:debug)
        allow(response).to receive(:headers).and_return({})
      end

      context "when specified" do
        let(:plugin_config) {
          super().merge({ "target" => "my-target" })
        }

        it "sets all query results into event" do
          expected_result = [
            {"id"=>"foo", "val"=>"bar", "odd"=>nil},
            {"id"=>"hello", "val"=>"again", "odd"=>"world"},
            {"id"=>"another", "val"=>"value", "odd"=>"here"}
          ]
          expect { esql_executor.process(client, event) }.to_not raise_error
          expect(event.get("[@metadata][total_values]")).to eq(3)
          expect(event.get("my-target").size).to eq(3)
          expect(event.get("my-target")).to eq(expected_result)
        end
      end

      context "when not specified" do
        shared_examples "first result into the event" do
          it "sets" do
            expect { esql_executor.process(client, event) }.to_not raise_error
            expect(event.get("[@metadata][total_values]")).to eq(3)
            expect(event.get("id")).to eq("foo")
            expect(event.get("val")).to eq("bar")
            expect(event.get("odd")).to eq(nil)
          end
        end
        context "when limit is included in the query" do
          let(:plugin_config) {
            super().merge({ "query" => "FROM my-index | LIMIT 555" })
          }
          it_behaves_like "first result into the event"
        end

        context "when limit is not included in the query" do
          let(:plugin_config) {
            super().merge({ "query" => "FROM my-index" })
          }
          it_behaves_like "first result into the event"
        end
      end
    end
  end

  describe "#query placeholders" do
    before(:each) do
      allow(logger).to receive(:debug)
      allow(logger).to receive(:warn)
      plugin.send(:validate_esql_query_and_params!)
    end

    context "when `query_params` is an Array contains {key => val} entries" do
      let(:plugin_config) {
        super()
          .merge(
            {
              "query" => "FROM my-index | LIMIT 1",
              "query_params" => [{ "a" => "b" }, { "c" => "[b]" }, { "e" => 1 }, { "f" => "[g]" }],
            })
      }

      it "separates references and static params at initialization" do
        expect(esql_executor.instance_variable_get(:@referenced_params)).to eq({"c" => "[b]", "f" => "[g]"})
        expect(esql_executor.instance_variable_get(:@static_params)).to eq([{"a" => "b"},  {"e" => 1}])
      end
    end

    context "when `query_params` is a Hash" do
      let(:plugin_config) {
        super()
          .merge(
            {
              "query" => "FROM my-index | LIMIT 1",
              "query_params" => { "a" => "b", "c" => "[b]", "e" => 1, "f" => "[g]" },
            })
      }

      it "separates references and static params at initialization" do
        expect(esql_executor.instance_variable_get(:@referenced_params)).to eq({"c" => "[b]", "f" => "[g]"})
        expect(esql_executor.instance_variable_get(:@static_params)).to eq([{"a" => "b"},  {"e" => 1}])
      end
    end
  end
end if LOGSTASH_VERSION >= LogStash::Filters::Elasticsearch::LS_ESQL_SUPPORT_VERSION