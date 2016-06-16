# encoding: utf-8
require "elasticsearch"
require "base64"

module LogStash
  module Filters
    class ElasticsearchClient

      attr_reader :client

      def initialize(user, password, options={})
        ssl     = options.fetch(:ssh, false)
        hosts   = options[:hosts]
        @logger = options[:logger]

        transport_options = {}
        if user && password
          token = ::Base64.strict_encode64("#{user}:#{password.value}")
          transport_options[:headers] = { Authorization: "Basic #{token}" }
        end

        host.map! {|h| { host: h, scheme: 'https' } } if ssl
        transport_options[:ssl] = { ca_file: options[:ca_file] } if ssl && options[:ca_file]

        @logger.info("New ElasticSearch filter", :hosts => hosts)
        @client = ::Elasticsearch::Client.new(hosts: hosts, transport_options: transport_options)
      end

      def search(params)
        @client.search(params)
      end

    end
  end
end
