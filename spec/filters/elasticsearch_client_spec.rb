# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/elasticsearch/client"

describe LogStash::Filters::ElasticsearchClient do
  let(:logger) do
    log = Object.new
    allow(log).to receive(:debug)
    allow(log).to receive(:info)
    allow(log).to receive(:warn)
    allow(log).to receive(:error)
    allow(log).to receive(:fatal)
    log
  end
  let(:options) do
    { hosts: ['localhost:9200'],
      logger: logger
    }
  end

  context "instantiating ElasticsearchClient" do
    it "should not raise an exception" do
      expect {
        LogStash::Filters::ElasticsearchClient.new(nil, nil, options)
      }.to_not raise_error
    end

    it "should add Authorization header when passing user/pass" do
      expect(::Elasticsearch::Client).to receive(:new) do |args|
        expect(args[:hosts]).to be_kind_of(Array)
        expect(args[:transport_options][:headers][:Authorization]).to match(/^Basic \S+$/)
      end
      LogStash::Filters::ElasticsearchClient.new('user', LogStash::Util::Password.new('pass'), options)
    end

    context 'when ssl is true' do
      let(:options) do
        super.merge(ssl: true)
      end

      it "should add https to schema-less hosts and accept hosts already with https" do
        expect(::Elasticsearch::Client).to receive(:new) do |args|
          expect(args[:hosts]).to eq(['https://example.org:9200', 'https://secure.example.org:9200'])
        end
        LogStash::Filters::ElasticsearchClient.new(nil, nil,
          options.merge(hosts: ['example.org:9200', 'https://secure.example.org:9200']))
      end

      it "should log an error and raise if any host has an http schema" do
        expect(logger).to receive(:error).with(/conflicting.*scheme/i, hash_including(:ssl, :hosts))
        expect {
          LogStash::Filters::ElasticsearchClient.new(nil, nil,
            options.merge(hosts: ['http://localhost:9200', 'example.org:9200']))
        }.to raise_error(LogStash::ConfigurationError)
      end
    end

    context 'when ssl is false' do
      let(:options) do
        super.merge(ssl: false)
      end

      it "should accept schema-less and http hosts and pass them along without modification" do
        expect(::Elasticsearch::Client).to receive(:new) do |args|
          expect(args[:hosts]).to eq(['http://example.org:9200', 'localhost:9200'])
        end
        LogStash::Filters::ElasticsearchClient.new(nil, nil,
          options.merge(hosts: ['http://example.org:9200', 'localhost:9200']))
      end

      # The behaviour remaining in this context has been in place for a while.
      # It is counter-intuitive, but fixing it is a breaking change and this
      # plugin's http subsystem is due to be rewritten anyway. So not the best
      # time to push out breaking changes on people.
      it "currently accept hosts with https schema" do
        expect(::Elasticsearch::Client).to receive(:new) do |args|
          expect(args[:hosts]).to eq(['https://example.org:9200'])
        end
        LogStash::Filters::ElasticsearchClient.new(nil, nil, options.merge(hosts: ['https://example.org:9200']))
      end

      it "should accept hosts with mixed schemas" do
        expect(::Elasticsearch::Client).to receive(:new) do |args|
          expect(args[:hosts]).to eq(['https://example.org:9200', 'http://localhost:9200'])
        end
        LogStash::Filters::ElasticsearchClient.new(nil, nil, options.merge(hosts: ['https://example.org:9200', 'http://localhost:9200']))
      end
    end

  end
end
