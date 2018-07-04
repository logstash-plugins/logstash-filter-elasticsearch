# encoding: utf-8
require "elasticsearch"
require "base64"


module LogStash
  module Filters
    class ElasticsearchClient

      attr_reader :client

      URI_TEMPLATE = '%{scheme}://%{host}'.freeze

      def initialize(user, password, options={})
        ElasticsearchClient.validate_config!(user, password, options)

        ssl     = options[:ssl]
        hosts   = options[:hosts]
        @logger = options[:logger]

        transport_options = {}
        if user && password
          token = ::Base64.strict_encode64("#{user}:#{password.value}")
          transport_options[:headers] = { Authorization: "Basic #{token}" }
        end

        if options[:ssl]
          hosts.map! do |h|
            if h.start_with?('https://')
              h
            else
              URI_TEMPLATE % { host: h, scheme: 'https' }
            end
          end
        end
        # set ca_file even if ssl isn't on, since the host can be an https url
        transport_options[:ssl] = { ca_file: options[:ca_file] } if options[:ca_file]

        @logger.info("New ElasticSearch filter client", :hosts => hosts)
        @client = ::Elasticsearch::Client.new(hosts: hosts, transport_options: transport_options)
      end

      def search(params)
        @client.search(params)
      end

      def self.validate_config!(user, password, options={})
        ssl     = options[:ssl]
        hosts   = options[:hosts]
        logger  = options[:logger]
        if ssl == true && hosts.any? {|h| h.start_with?('http://') }
          logger.error "SSL option was set to true but a host " +
            "was also declared with a conflicting scheme, http://. " +
            "Please reconcile this.", ssl: ssl, hosts: hosts
          raise LogStash::ConfigurationError, "Aborting due to conflicting configuration"
        end
      end

    end
  end
end
