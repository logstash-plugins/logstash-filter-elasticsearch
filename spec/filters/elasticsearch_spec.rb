# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin"
require "logstash/filters/elasticsearch"
require "logstash/json"
require "cabin"
require "webrick"
require "uri"

describe LogStash::Filters::Elasticsearch do

  subject(:plugin) { described_class.new(config) }

  let(:event)  { LogStash::Event.new({}) }

  context "registration" do

    let(:plugin) { LogStash::Plugin.lookup("filter", "elasticsearch").new(config) }

    context "against authentic Elasticsearch" do
      let(:config) { { "query" => "*" } }

      before do
        allow(plugin).to receive(:test_connection!)
        allow(plugin).to receive(:setup_serverless)
      end
      
      it "should not raise an exception" do
        expect {plugin.register}.to_not raise_error
      end
    end

    context "against not authentic Elasticsearch" do
      let(:config) { { "query" => "*" } }
      let(:failing_client) do
        client = double("client")
        allow(client).to receive(:ping).and_raise Elasticsearch::UnsupportedProductError

        client_wrapper = double("filter_client")
        allow(client_wrapper).to receive(:client).and_return client
        client_wrapper
      end

      before do
        allow(plugin).to receive(:get_client).and_return(failing_client)
      end

      it "should raise ConfigurationError" do
        expect {plugin.register}.to raise_error(LogStash::ConfigurationError)
      end
    end

    context "against serverless Elasticsearch" do
      let(:config) { { "query" => "*" } }
      let(:filter_client) { double("filter_client") }
      let(:es_client) { double("es_client") }

      before do
        allow(plugin).to receive(:test_connection!)
        allow(plugin).to receive(:get_client).and_return(filter_client)
        allow(filter_client).to receive(:serverless?).and_return(true)
        allow(filter_client).to receive(:client).and_return(es_client)

        if elastic_ruby_v8_client_available?
          allow(es_client).to receive(:info)
                                .with(a_hash_including(
                                        :headers => LogStash::Filters::ElasticsearchClient::DEFAULT_EAV_HEADER))
                                .and_raise(Elastic::Transport::Transport::Errors::BadRequest.new)
        else
          allow(es_client).to receive(:info)
                                .with(a_hash_including(
                                        :headers => LogStash::Filters::ElasticsearchClient::DEFAULT_EAV_HEADER))
                                .and_raise(Elasticsearch::Transport::Transport::Errors::BadRequest.new)
        end
      end

      it "raises an exception when Elastic Api Version is not supported" do
        expect {plugin.register}.to raise_error(LogStash::ConfigurationError)
      end
    end

    context "query settings" do
      it "raise an exception when query and query_template are empty" do
        plugin = described_class.new({})
        expect {plugin.register}.to raise_error(LogStash::ConfigurationError)
      end

      it "raise an exception when query and query_template are set" do
        config = { "query" => "*", "query_template" => File.join(File.dirname(__FILE__), "fixtures", "query_template_unicode.json") }
        plugin = described_class.new(config)
        expect {plugin.register}.to raise_error(LogStash::ConfigurationError)
      end
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

    let(:response) do
      LogStash::Json.load(File.read(File.join(File.dirname(__FILE__), "fixtures", "request_x_1.json")))
    end

    let(:client) { double(:client) }

    before(:each) do
      allow(LogStash::Filters::ElasticsearchClient).to receive(:new).and_return(client)
      if elastic_ruby_v8_client_available?
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

    context 'with client-level retries' do
      let(:config) do
        super().merge(
          "retry_on_failure" => 3,
          "retry_on_status" => [500]
        )
      end
    end

    context "with custom headers" do
      let(:config) do
        {
          "query" => "*",
          "custom_headers" => { "Custom-Header-1" => "Custom Value 1", "Custom-Header-2" => "Custom Value 2" }
        }
      end

      let(:plugin) { LogStash::Filters::Elasticsearch.new(config) }
      let(:client_double) { double("client") }
      let(:transport_double) { double("transport", options: { transport_options: { headers: config["custom_headers"] } }) }

      before do
        allow(plugin).to receive(:get_client).and_return(client_double)
        if elastic_ruby_v8_client_available?
          allow(client_double).to receive(:es_transport_client_type).and_return('elastic_transport')
        else
          allow(client_double).to receive(:es_transport_client_type).and_return('elasticsearch_transport')
        end
        allow(client_double).to receive(:client).and_return(transport_double)
      end

      it "sets custom headers" do
        plugin.register
        client = plugin.send(:get_client).client
        expect(client.options[:transport_options][:headers]).to match(hash_including(config["custom_headers"]))
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

  class StoppableServer

    attr_reader :port

    def initialize()
      queue = Queue.new
      @first_req_waiter = java.util.concurrent.CountDownLatch.new(1)
      @first_request = nil

      @t = java.lang.Thread.new(
        proc do
          begin
            @server = WEBrick::HTTPServer.new :Port => 0, :DocumentRoot => ".",
                     :Logger => Cabin::Channel.get, # silence WEBrick logging
                     :StartCallback => Proc.new {
                           queue.push("started")
                         }
            @port = @server.config[:Port]
            @server.mount_proc '/' do |req, res|
              res.body = '''
              {
                  "name": "ce7ccfb438e8",
                  "cluster_name": "docker-cluster",
                  "cluster_uuid": "DyR1hN03QvuCWXRy3jtb0g",
                  "version": {
                      "number": "7.13.1",
                      "build_flavor": "default",
                      "build_type": "docker",
                      "build_hash": "9a7758028e4ea59bcab41c12004603c5a7dd84a9",
                      "build_date": "2021-05-28T17:40:59.346932922Z",
                      "build_snapshot": false,
                      "lucene_version": "8.8.2",
                      "minimum_wire_compatibility_version": "6.8.0",
                      "minimum_index_compatibility_version": "6.0.0-beta1"
                  },
                  "tagline": "You Know, for Search"
              }
              '''
              res.status = 200
              res['Content-Type'] = 'application/json'
              @first_request = req
              @first_req_waiter.countDown()
            end

            @server.start
          rescue => e
            puts "Error in webserver thread #{e}"
            # ignore
          end
        end
      )
      @t.daemon = true
      @t.start
      queue.pop # blocks until the server is up
    end

    def stop
      @server.shutdown
    end

    def wait_receive_request
      @first_req_waiter.await(2, java.util.concurrent.TimeUnit::SECONDS)
      @first_request
    end
  end

  describe "user-agent header" do
    let!(:webserver) { StoppableServer.new } # webserver must be started before the call, so no lazy "let"

    after :each do
      webserver.stop
    end

    it "server should be started" do
      require 'net/http'
      response = nil
      Net::HTTP.start('localhost', webserver.port) {|http|
        response = http.request_get('/')
      }
      expect(response.code.to_i).to eq(200)
    end

    context "used by plugin" do
      let(:config) do
        {
          "hosts" => ["localhost:#{webserver.port}"],
          "query" => "response: 404",
          "fields" => { "response" => "code" },
          "docinfo_fields" => { "_index" => "es_index" },
          "aggregation_fields" => { "bytes_avg" => "bytes_avg_ls_field" }
        }
      end
      let(:plugin) { described_class.new(config) }
      let(:event)  { LogStash::Event.new({}) }

      # elasticsearch-ruby 7.17.9 initialize two user agent headers, `user-agent` and `User-Agent`
      # hence, fail this header size test case
      xit "client should sent the expect user-agent" do
        plugin.register

        request = webserver.wait_receive_request

        expect(request.header['user-agent'].size).to eq(1)
        expect(request.header['user-agent'][0]).to match(/logstash\/\d*\.\d*\.\d* \(OS=.*; JVM=.*\) logstash-filter-elasticsearch\/\d*\.\d*\.\d*/)
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
      allow(plugin).to receive(:setup_serverless)
    end

    after(:each) do
      Thread.current[:filter_elasticsearch_client] = nil
    end

    it 'uses a threadsafe transport adapter' do
      client = plugin.send(:get_client).client
      # we currently rely on the threadsafety guarantees provided by Manticore
      # this spec is a safeguard to trigger an assessment of thread-safety should
      # we choose a different transport adapter in the future.
      transport_class = extract_transport(client).options.fetch(:transport_class)
      if elastic_ruby_v8_client_available?
        allow(client).to receive(:es_transport_client_type).and_return("elastic_transport")
        expect(transport_class).to equal ::Elastic::Transport::Transport::HTTP::Manticore
      else
        expect(transport_class).to equal ::Elasticsearch::Transport::Transport::HTTP::Manticore
      end
    end

    it 'uses a client with sufficient connection pool size' do
      client = plugin.send(:get_client).client
      transport_options = extract_transport(client).options.fetch(:transport_options)
      # pool_max and pool_max_per_route are manticore-specific transport options
      expect(transport_options).to include(:pool_max => 1000, :pool_max_per_route => 100)
    end

    it 'uses a single shared client across threads' do
      q = Queue.new
      10.times.map do
        Thread.new(plugin) { |instance| q.push instance.send(:get_client) }
      end.map(&:join)

      first = q.pop
      expect(q.pop).to be(first) until q.empty?
    end

    describe "cloud.id" do
      let(:valid_cloud_id) do
        'sample:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlvJGFjMzFlYmI5MDI0MTc3MzE1NzA0M2MzNGZkMjZmZDQ2OjkyNDMkYTRjMDYyMzBlNDhjOGZjZTdiZTg4YTA3NGEzYmIzZTA6OTI0NA=='
      end

      let(:config) { super().merge({ 'cloud_id' => valid_cloud_id }) }

      it "should set host(s)" do
        plugin.register
        client = plugin.send(:get_client).client
        expect( extract_transport(client).hosts ).to eql [{
                                                     :scheme => "https",
                                                     :host => "ac31ebb90241773157043c34fd26fd46.us-central1.gcp.cloud.es.io",
                                                     :port => 9243,
                                                     :path => "",
                                                     :protocol => "https"
                                                 }]
      end

      context 'invalid' do
        let(:config) { super().merge({ 'cloud_id' => 'invalid:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlv' }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /cloud_id.*? is invalid/
        end
      end

      context 'hosts also set' do
        let(:config) { super().merge({ 'cloud_id' => valid_cloud_id, 'hosts' => [ 'localhost:9200' ] }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /cloud_id and hosts/
        end
      end
    end if LOGSTASH_VERSION > '6.0'

    describe "cloud.auth" do
      let(:config) { super().merge({ 'cloud_auth' => LogStash::Util::Password.new('elastic:my-passwd-00') }) }

      it "should set authorization" do
        plugin.register
        client = plugin.send(:get_client).client
        auth_header = extract_transport(client).options[:transport_options][:headers]['Authorization']

        expect( auth_header ).to eql "Basic #{Base64.encode64('elastic:my-passwd-00').rstrip}"
      end

      context 'invalid' do
        let(:config) { super().merge({ 'cloud_auth' => 'invalid-format' }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /cloud_auth.*? format/
        end
      end

      context 'user also set' do
        let(:config) { super().merge({ 'cloud_auth' => 'elastic:my-passwd-00', 'user' => 'another' }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /Multiple authentication options are specified/
        end
      end
    end if LOGSTASH_VERSION > '6.0'

    describe "api_key" do
      context "without ssl" do
        let(:config) { super().merge({ 'api_key' => LogStash::Util::Password.new('foo:bar') }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /api_key authentication requires SSL\/TLS/
        end
      end

      context "with ssl" do
        let(:config) { super().merge({ 'api_key' => LogStash::Util::Password.new('foo:bar'), "ssl_enabled" => true }) }

        it "should set authorization" do
          plugin.register
          client = plugin.send(:get_client).client
          auth_header = extract_transport(client).options[:transport_options][:headers]['Authorization']

          expect( auth_header ).to eql "ApiKey #{Base64.strict_encode64('foo:bar')}"
        end

        context 'user also set' do
          let(:config) { super().merge({ 'api_key' => 'foo:bar', 'user' => 'another' }) }

          it "should fail" do
            expect { plugin.register }.to raise_error LogStash::ConfigurationError, /Multiple authentication options are specified/
          end
        end
      end
    end if LOGSTASH_VERSION > '6.0'

    describe "proxy" do
      context 'valid' do
        let(:config) { super().merge({ 'proxy' => 'http://localhost:1234' }) }

        it "should set proxy" do
          plugin.register
          client = plugin.send(:get_client).client
          proxy = extract_transport(client).options[:transport_options][:proxy]

          expect( proxy ).to eql "http://localhost:1234"
        end
      end

      context 'invalid' do
        let(:config) { super().merge({ 'proxy' => '${A_MISSING_ENV_VAR:}' }) }

        it "should not set proxy" do
          plugin.register
          client = plugin.send(:get_client).client

          expect( extract_transport(client).options[:transport_options] ).to_not include(:proxy)
        end
      end
    end

    describe "retry_on_failure" do
      let(:config) { super().merge("retry_on_failure" => 3) }

      it 'propagates to the client' do
        plugin.register

        client = plugin.send(:get_client).client
        expect( extract_transport(client).options[:retry_on_failure] ).to eq(3)
      end
    end

    describe "retry_on_status" do
      let(:config) { super().merge("retry_on_status" => [500, 502, 503, 504]) }

      it 'propagates to the client' do
        plugin.register

        client = plugin.send(:get_client).client
        expect( extract_transport(client).options[:retry_on_status] ).to eq([500, 502, 503, 504])
      end
    end
  end

  describe "Elastic Api and Product Origin Headers" do
    let(:config) { {"query" => "*"} }
    let(:plugin) { described_class.new(config) }
    let(:headers) {{'x-elastic-product' => 'Elasticsearch'}}
    let(:cluster_info) { {"version" => {"number" => "8.10.0", "build_flavor" => build_flavor}, "tagline" => "You Know, for Search"} }
    let(:mock_resp) { MockResponse.new(200, cluster_info, headers) }

    before do
      expect(plugin).to receive(:test_connection!)
    end

    context "serverless" do
      let(:build_flavor) { "serverless" }

      before do
        allow_any_instance_of(Elasticsearch::Client).to receive(:perform_request).with(any_args).and_return(mock_resp)
      end

      it 'propagates header to es client' do
        plugin.register
        client = plugin.send(:get_client).client
        expect( extract_transport(client).options[:transport_options][:headers] ).to match hash_including("Elastic-Api-Version" => "2023-10-31")
        expect( extract_transport(client).options[:transport_options][:headers] )
          .to match hash_including("x-elastic-product-origin" => "logstash-filter-elasticsearch")
      end
    end

    context "stateful" do
      let(:build_flavor) { "default" }

      before do
        expect_any_instance_of(Elasticsearch::Client).to receive(:perform_request).with(any_args).and_return(mock_resp)
      end

      it 'does not propagate Elastic-Api-Version header to es client' do
        plugin.register
        client = plugin.send(:get_client).client
        expect( extract_transport(client).options[:transport_options][:headers] ).to match hash_not_including("Elastic-Api-Version" => "2023-10-31")
        expect( extract_transport(client).options[:transport_options][:headers] )
          .to match hash_including("x-elastic-product-origin" => "logstash-filter-elasticsearch")
      end
    end

  end

  describe "ca_trusted_fingerprint" do
    let(:ca_trusted_fingerprint) { SecureRandom.hex(32) }
    let(:config) { {"ssl_enabled" => true, "ca_trusted_fingerprint" => ca_trusted_fingerprint, "query" => "*"}}

    subject(:plugin) { described_class.new(config) }

    if Gem::Version.create(LOGSTASH_VERSION) >= Gem::Version.create("8.3.0")
      context 'the generated trust_strategy' do
        before(:each) do
          allow(plugin).to receive(:test_connection!)
          allow(plugin).to receive(:setup_serverless)
        end

        it 'is passed to the Manticore client' do
          expect(Manticore::Client).to receive(:new)
                                         .with(
                                           a_hash_including(
                                             ssl: a_hash_including(
                                               trust_strategy: plugin.trust_strategy_for_ca_trusted_fingerprint
                                             )
                                           )
                                         ).and_call_original
          plugin.register

          # the client is built lazily, so we need to get it explicitly
          plugin.send(:get_client).client
        end
      end
    else
      it 'raises a configuration error' do
        expect { plugin }.to raise_exception(LogStash::ConfigurationError, a_string_including("ca_trusted_fingerprint"))
      end
    end
  end

  describe "keystore and keystore_password" do
    let(:keystore_path) { Pathname.new("fixtures/test_certs/ls.chain.p12").expand_path(__dir__).cleanpath.to_s }
    let(:keystore_password) { '12345678' }

    let(:config) do
      {
        'hosts' => 'https://localhost:9200',
        'ssl_keystore_path' => keystore_path,
        'ssl_keystore_password' => keystore_password,
        'query' => '*'
      }
    end

    subject(:plugin) { described_class.new(config) }

    before(:each) do
      allow(plugin).to receive(:test_connection!)
      allow(plugin).to receive(:setup_serverless)
    end

    it 'is passed to the Manticore client' do
      expect(Manticore::Client).to receive(:new)
                                     .with(
                                       a_hash_including(
                                         ssl: a_hash_including(
                                           keystore: keystore_path,
                                           keystore_password: keystore_password
                                         )
                                       )
                                     ).and_call_original

      allow(plugin.logger).to receive(:debug).and_call_original
      expect(plugin.logger).to receive(:debug).with(a_string_including('Keystore for client certificate'), anything)

      plugin.register

      # the client is built lazily, so we need to get it explicitly
      plugin.send(:get_client).client
    end
  end

  describe "defaults" do

    let(:config) { {"query" => "*"} }
    let(:plugin) { described_class.new(config) }

    before do
      allow(plugin).to receive(:test_connection!)
      allow(plugin).to receive(:setup_serverless)
    end

    it "should set localhost:9200 as hosts" do
      plugin.register
      client = plugin.send(:get_client).client
      hosts = extract_transport(client).hosts
      expect( hosts.size ).to be 1
      expect( hosts[0] ).to include(:host => "localhost", :port => 9200, :scheme => "http")
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
      if elastic_ruby_v8_client_available?
        allow(client).to receive(:es_transport_client_type).and_return('elastic_transport')
      else
        allow(client).to receive(:es_transport_client_type).and_return('elasticsearch_transport')
      end
      allow(plugin).to receive(:test_connection!)
      allow(plugin).to receive(:setup_serverless)
      plugin.register
    end

    it "should read and send non-ascii query" do
      expect(client).to receive(:search).with({
          :body => { "query" => { "terms" => { "lock" => [ "잠금", "uzávěr" ] } } },
          :index => ""})

      plugin.filter(LogStash::Event.new)
    end
  end

  def extract_transport(client)
    # on 7x: client.transport.transport
    # on >=8.x: client.transport
    client.transport.respond_to?(:transport) ? client.transport.transport : client.transport
  end

  def elastic_ruby_v8_client_available?
    Elasticsearch::Transport
    false
  rescue NameError # NameError: uninitialized constant Elasticsearch::Transport if Elastic Ruby client is not available
    true
  end

  class MockResponse
    attr_reader :code, :headers

    def initialize(code = 200, body = nil, headers = {})
      @code = code
      @body = body
      @headers = headers
    end

    def body
      @body
    end

    def status
      @code
    end
  end
end
