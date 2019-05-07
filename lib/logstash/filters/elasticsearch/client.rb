# encoding: utf-8
require 'elasticsearch'
require 'base64'
require 'elasticsearch/transport/transport/http/manticore'
require 'faraday_middleware/aws_sigv4'


module LogStash
  module Filters
    class ElasticsearchClient

      attr_reader :client

      def initialize(user, password, options={})
        ssl     = options.fetch(:ssl, false)
        hosts   = options[:hosts]
        @logger = options[:logger]

        aws_access_key_id = options[:aws_access_key_id]
        aws_secret_access_key = options[:aws_secret_access_key]
        region = options[:region]

        transport_options = {}
        if user && password
          token = ::Base64.strict_encode64("#{user}:#{password.value}")
          transport_options[:headers] = { Authorization: "Basic #{token}" }
        end

        hosts = hosts.map {|h| { host: h, scheme: 'https' } } if ssl
        # set ca_file even if ssl isn't on, since the host can be an https url
        ssl_options = { ssl: true, ca_file: options[:ca_file] } if options[:ca_file]
        ssl_options ||= {}

        if aws_access_key_id && aws_secret_access_key && region
          @logger.info("New AWS ElasticSearch filter client", hosts: hosts)
          @client = ::Elasticsearch::Client.new( hosts: hosts, port:443 ) do |f|
            f.request(
              :aws_sigv4,
              service: 'es',
              region: region,
              access_key_id: aws_access_key_id,
              secret_access_key: aws_secret_access_key
            )
          end
        else
        @logger.info("New ElasticSearch filter client", hosts: hosts)
          @client = ::Elasticsearch::Client.new(
            hosts: hosts,
            transport_options: transport_options,
            transport_class: ::Elasticsearch::Transport::Transport::HTTP::Manticore,
            ssl: ssl_options
          )
        end
      end

      def search(params)
        @client.search(params)
      end

    end
  end
end
