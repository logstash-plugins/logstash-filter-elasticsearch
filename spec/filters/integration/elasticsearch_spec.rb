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
    if SECURE_INTEGRATION
      { 'user' => 'tests', 'password' => 'Tests123' } # added user
    else
      { 'user' => 'elastic', 'password' => ENV['ELASTIC_PASSWORD'] }
    end
  end

  let(:config) do
    config = ELASTIC_SECURITY_ENABLED ? base_config.merge(credentials) : base_config
    config = { 'ssl_certificate_authorities' => ca_path }.merge(config) if SECURE_INTEGRATION
    config
  end

  let(:ca_path) do
    File.expand_path('../fixtures/test_certs/ca.crt', File.dirname(__FILE__))
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
    doc_args = "#{args} -H 'Content-Type: application/json' -d '{\"response\": 404, \"this\":\"that\"}'"
    10.times do
      ESHelper.curl_and_get_json_response "#{es_url}/logs/_doc", method: 'POST', args: doc_args
    end
    ESHelper.curl_and_get_json_response "#{es_url}/_refresh", method: 'POST', args: args
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

  context 'setting host:port (and ssl)' do # reproduces GH-155

    let(:config) do
      super().merge "hosts" => [ESHelper.get_host_port], "ssl_enabled" => SECURE_INTEGRATION
    end

    it "works" do
      expect { plugin.register }.to_not raise_error
      plugin.filter(event)
    end

  end

  if SECURE_INTEGRATION
    context 'setting keystore' do
      let(:keystore_path) { Pathname.new("../fixtures/test_certs/ls.chain.p12").expand_path(__dir__).cleanpath.to_s }
      let(:keystore_password) { '12345678' }

      let(:config) do
        super().merge(
          "hosts" => [ESHelper.get_host_port],
          "ssl_keystore_path" => keystore_path,
          "ssl_keystore_password" => keystore_password,
          "ssl_enabled" => true,
          "fields" => { "this" => "contents", "response" => "four-oh-four" }
        )
      end

      it "should enhance the current event with new data" do
        plugin.register
        plugin.filter(event)
        puts event.to_hash.inspect
        expect(event.get('contents')).to eq('that')
        expect(event.get('four-oh-four')).to eq(404)
      end
    end

    if Gem::Version.create(LOGSTASH_VERSION) >= Gem::Version.create("8.3.0")
      context 'setting ca_trusted_finterprint WITHOUT ca_file' do
        let(:ca_trusted_fingerprint) { Pathname.new("../fixtures/test_certs/ca.der.sha256").expand_path(__dir__).read.chomp }

        let(:config) do
          bc = super()
          bc.delete('ssl_certificate_authorities')
          bc.merge({
            'ca_trusted_fingerprint' => ca_trusted_fingerprint,
            'fields' => { "this" => "contents", "response" => "four-oh-four" }
          })
        end

        it "should enhance the current event with new data" do
          puts config.inspect
          plugin.register
          plugin.filter(event)
          puts event.to_hash.inspect
          expect(event.get('contents')).to eq('that')
          expect(event.get('four-oh-four')).to eq(404)
        end
      end
    end
  end

end
