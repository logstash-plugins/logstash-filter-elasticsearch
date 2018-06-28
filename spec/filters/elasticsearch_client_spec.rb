# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/elasticsearch/client"

def password(pass)

end

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

    it "should accept schema-less hosts and pass them along without modification" do
      expect(::Elasticsearch::Client).to receive(:new) do |args|
        expect(args[:hosts]).to eq(['example.org:9200'])
      end
      LogStash::Filters::ElasticsearchClient.new(nil, nil, options.merge(hosts: ['example.org:9200']))
    end

    it "should accept hosts with http schema" do
      expect(::Elasticsearch::Client).to receive(:new) do |args|
        expect(args[:hosts]).to eq(['http://example.org:9200'])
      end
      LogStash::Filters::ElasticsearchClient.new(nil, nil, options.merge(hosts: ['http://example.org:9200']))
    end

    it "should accept hosts with https schema" do
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

    it "should add https to schema-less hosts when specifying ssl true"
    it "should log an error and raise, when specifying a schema in at least one host, and setting ssl true"
    it "should log an error and raise, when specifying a schema in at least one host, and setting ssl false"

  end
end
