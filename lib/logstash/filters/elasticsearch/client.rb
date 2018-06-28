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

        hosts.map! {|h| URI_TEMPLATE % { host: h, scheme: 'https' } } if ssl
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
        unless ssl.nil?
          if hosts.detect {|h| h =~ %r(^https?://) }
            logger.error "Conflicting configuration detected: " +
              "you cannot specify a schema in your hosts and set the 'ssl' option at the same time. " +
              "You must use one or the other.", ssl: ssl, hosts: hosts
            raise LogStash::ConfigurationError, "Aborting due to conflicting configuration"
          end
        end
      end

    end
  end
end
