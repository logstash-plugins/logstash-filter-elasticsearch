# encoding: utf-8
require "elasticsearch"
require "base64"
require "elasticsearch/transport/transport/http/manticore"


module LogStash
  module Filters
    class ElasticsearchClient

      attr_reader :client

      BUILD_FLAVOR_SERVERLESS = 'serverless'.freeze
      DEFAULT_EAV_HEADER = { "Elastic-Api-Version" => "2023-10-31" }.freeze

      def initialize(logger, hosts, options = {})
        user = options.fetch(:user, nil)
        password = options.fetch(:password, nil)
        api_key = options.fetch(:api_key, nil)
        proxy = options.fetch(:proxy, nil)
        user_agent = options[:user_agent]

        transport_options = { }
        transport_options[:headers] = options.fetch(:serverless, false) ?  DEFAULT_EAV_HEADER.dup : {}
        transport_options[:headers].merge!(setup_basic_auth(user, password))
        transport_options[:headers].merge!(setup_api_key(api_key))
        transport_options[:headers].merge!({ 'user-agent' => "#{user_agent}" })

        transport_options[:pool_max] = 1000
        transport_options[:pool_max_per_route] = 100

        logger.warn "Supplied proxy setting (proxy => '') has no effect" if @proxy.eql?('')
        transport_options[:proxy] = proxy.to_s if proxy && !proxy.eql?('')

        ssl_options = options.fetch(:ssl, { :enabled => false })
        ssl_enabled = ssl_options.fetch(:enabled, false)

        hosts = setup_hosts(hosts, ssl_enabled)

        client_options = {
                       hosts: hosts,
             transport_class: ::Elasticsearch::Transport::Transport::HTTP::Manticore,
           transport_options: transport_options,
                         ssl: ssl_options,
            retry_on_failure: options[:retry_on_failure],
             retry_on_status: options[:retry_on_status]
        }

        logger.info("New ElasticSearch filter client", :hosts => hosts)
        @client = ::Elasticsearch::Client.new(client_options)
      end

      def search(params={})
        @client.search(params)
      end

      def info
        @client.info
      end

      def build_flavor
        @build_flavor ||= info&.dig('version', 'build_flavor')
      end

      def serverless?
        @is_serverless ||= (build_flavor == BUILD_FLAVOR_SERVERLESS)
      end

      private

      def setup_hosts(hosts, ssl_enabled)
        hosts = Array(hosts).map { |host| host.to_s } # potential SafeURI#to_s
        hosts.map do |h|
          if h.start_with?('http:/', 'https:/')
            h
          else
            host, port = h.split(':')
            { host: host, port: port, scheme: (ssl_enabled ? 'https' : 'http') }
          end
        end
      end

      def setup_basic_auth(user, password)
        return {} unless user && password && password.value

        token = ::Base64.strict_encode64("#{user}:#{password.value}")
        { 'Authorization' => "Basic #{token}" }
      end

      def setup_api_key(api_key)
        return {} unless (api_key && api_key.value)

        token = ::Base64.strict_encode64(api_key.value)
        { 'Authorization' => "ApiKey #{token}" }
      end
    end
  end
end
