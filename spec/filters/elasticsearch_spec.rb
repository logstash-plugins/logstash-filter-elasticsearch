# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin"
require "logstash/filters/elasticsearch"
require "logstash/json"

describe LogStash::Filters::Elasticsearch do

  context "registration" do

    let(:plugin) { LogStash::Plugin.lookup("filter", "elasticsearch").new({}) }
    before do
      allow(plugin).to receive(:test_connection!)
    end

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
      allow(plugin).to receive(:test_connection!)
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

    context 'when Elasticsearch 7.x gives us a totals object instead of an integer' do
      let(:config) do
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

  describe "client" do
    let(:config) do
      {
          "query" => "response: unknown"
      }
    end
    let(:plugin) { described_class.new(config) }
    let(:event)  { LogStash::Event.new({}) }

    before(:each) do
      allow(plugin).to receive(:test_connection!)
    end

    after(:each) do
      Thread.current[:filter_elasticsearch_client] = nil
    end

    describe "cloud.id" do
      let(:valid_cloud_id) do
        'sample:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlvJGFjMzFlYmI5MDI0MTc3MzE1NzA0M2MzNGZkMjZmZDQ2OjkyNDMkYTRjMDYyMzBlNDhjOGZjZTdiZTg4YTA3NGEzYmIzZTA6OTI0NA=='
      end

      let(:config) { super.merge({ 'cloud_id' => valid_cloud_id }) }

      it "should set host(s)" do
        plugin.register
        client = plugin.send(:get_client).client
        expect( client.transport.hosts ).to eql [{
                                                     :scheme => "https",
                                                     :host => "ac31ebb90241773157043c34fd26fd46.us-central1.gcp.cloud.es.io",
                                                     :port => 9243,
                                                     :path => "",
                                                     :protocol => "https"
                                                 }]
      end

      context 'invalid' do
        let(:config) { super.merge({ 'cloud_id' => 'invalid:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlv' }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /cloud_id.*? is invalid/
        end
      end

      context 'hosts also set' do
        let(:config) { super.merge({ 'cloud_id' => valid_cloud_id, 'hosts' => [ 'localhost:9200' ] }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /cloud_id and hosts/
        end
      end
    end if LOGSTASH_VERSION > '6.0'

    describe "cloud.auth" do
      let(:config) { super.merge({ 'cloud_auth' => LogStash::Util::Password.new('elastic:my-passwd-00') }) }

      it "should set authorization" do
        plugin.register
        client = plugin.send(:get_client).client
        auth_header = client.transport.options[:transport_options][:headers][:Authorization]

        expect( auth_header ).to eql "Basic #{Base64.encode64('elastic:my-passwd-00').rstrip}"
      end

      context 'invalid' do
        let(:config) { super.merge({ 'cloud_auth' => 'invalid-format' }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /cloud_auth.*? format/
        end
      end

      context 'user also set' do
        let(:config) { super.merge({ 'cloud_auth' => 'elastic:my-passwd-00', 'user' => 'another' }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /Multiple authentication options are specified/
        end
      end
    end if LOGSTASH_VERSION > '6.0'

    describe "api_key" do
      context "without ssl" do
        let(:config) { super.merge({ 'api_key' => LogStash::Util::Password.new('foo:bar') }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /api_key authentication requires SSL\/TLS/
        end
      end

      context "with ssl" do
        let(:config) { super.merge({ 'api_key' => LogStash::Util::Password.new('foo:bar'), "ssl" => true }) }

        it "should set authorization" do
          plugin.register
          client = plugin.send(:get_client).client
          auth_header = client.transport.options[:transport_options][:headers][:Authorization]

          expect( auth_header ).to eql "ApiKey #{Base64.strict_encode64('foo:bar')}"
        end

        context 'user also set' do
          let(:config) { super.merge({ 'api_key' => 'foo:bar', 'user' => 'another' }) }

          it "should fail" do
            expect { plugin.register }.to raise_error LogStash::ConfigurationError, /Multiple authentication options are specified/
          end
        end
      end
    end if LOGSTASH_VERSION > '6.0'

    describe "proxy" do
      let(:config) { super.merge({ 'proxy' => 'http://localhost:1234' }) }

      it "should set proxy" do
        plugin.register
        client = plugin.send(:get_client).client
        proxy = client.transport.options[:transport_options][:proxy]

        expect( proxy ).to eql "http://localhost:1234"
      end

      context 'invalid' do
        let(:config) { super.merge({ 'proxy' => '${A_MISSING_ENV_VAR:}' }) }

        it "should not set proxy" do
          plugin.register
          client = plugin.send(:get_client).client

          expect( client.transport.options[:transport_options] ).to_not include(:proxy)
        end
      end
    end
  end

  describe "query template" do
    let(:config) do
      {
          "query_template" => File.join(File.dirname(__FILE__), "fixtures", "query_template_unicode.json"),
      }
    end

    let(:plugin) { described_class.new(config) }

    let(:client) { double(:client) }

    before(:each) do
      allow(LogStash::Filters::ElasticsearchClient).to receive(:new).and_return(client)
      allow(plugin).to receive(:test_connection!)
      plugin.register
    end

    it "should read and send non-ascii query" do
      expect(client).to receive(:search).with(
          :body => { "query" => { "terms" => { "lock" => [ "잠금", "uzávěr" ] } } },
          :index => "")

      plugin.filter(LogStash::Event.new)
    end
  end
end
