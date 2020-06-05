# encoding: utf-8
require "elasticsearch"
require "base64"
require "elasticsearch/transport/transport/http/manticore"


module LogStash
  module Filters
    class ElasticsearchClient

      attr_reader :client

      def initialize(logger, hosts, options = {})
        ssl = options.fetch(:ssl, false)
        user = options.fetch(:user, nil)
        password = options.fetch(:password, nil)
        api_key = options.fetch(:api_key, nil)

        transport_options = {:headers => {}}
        transport_options[:headers].merge!(setup_basic_auth(user, password))
        transport_options[:headers].merge!(setup_api_key(api_key))

	# Avoid nesting hosts. Issue #129
	if ssl
  	  hosts.map! do |h|
    	    h.is_a?(Hash) ? h : { host: h, scheme: 'https' } 
  	  end
	end
	
        # set ca_file even if ssl isn't on, since the host can be an https url
        ssl_options = { ssl: true, ca_file: options[:ca_file] } if options[:ca_file]
        ssl_options ||= {}

        logger.info("New ElasticSearch filter client", :hosts => hosts)
        @client = ::Elasticsearch::Client.new(hosts: hosts, transport_options: transport_options, transport_class: ::Elasticsearch::Transport::Transport::HTTP::Manticore, :ssl => ssl_options)
      end

      def search(params)
        @client.search(params)
      end

      private

      def setup_basic_auth(user, password)
        return {} unless user && password && password.value

        token = ::Base64.strict_encode64("#{user}:#{password.value}")
        { Authorization: "Basic #{token}" }
      end

      def setup_api_key(api_key)
        return {} unless (api_key && api_key.value)

        token = ::Base64.strict_encode64(api_key.value)
        { Authorization: "ApiKey #{token}" }
      end
    end
  end
end
