# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/json"
require 'logstash/plugin_mixins/ecs_compatibility_support'
require 'logstash/plugin_mixins/ecs_compatibility_support/target_check'
require 'logstash/plugin_mixins/ca_trusted_fingerprint_support'
require 'logstash/plugin_mixins/validator_support/field_reference_validation_adapter'
require "monitor"

require_relative "elasticsearch/client"

class LogStash::Filters::Elasticsearch < LogStash::Filters::Base

  require 'logstash/filters/elasticsearch/dsl_executor'
  require 'logstash/filters/elasticsearch/esql_executor'

  include LogStash::PluginMixins::ECSCompatibilitySupport
  include LogStash::PluginMixins::ECSCompatibilitySupport::TargetCheck

  config_name "elasticsearch"

  # List of elasticsearch hosts to use for querying.
  config :hosts, :validate => :array, :default => [ 'localhost:9200' ]

  # Comma-delimited list of index names to search; use `_all` or empty string to perform the operation on all indices.
  # Field substitution (e.g. `index-name-%{date_field}`) is available
  config :index, :validate => :string, :default => ""

  # A type of Elasticsearch query, provided by @query.
  config :query_type, :validate => %w[esql dsl], :default => "dsl"

  # Elasticsearch query string. This can be in DSL or ES|QL query shape defined by @query_type.
  # Read the Elasticsearch query string documentation.
  #   DSL: https://www.elastic.co/guide/en/elasticsearch/reference/master/query-dsl-query-string-query.html#query-string-syntax
  #   ES|QL: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
  config :query, :validate => :string

  # File path to elasticsearch query in DSL format. Read the Elasticsearch query documentation
  # for more info at: https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html
  config :query_template, :validate => :string

  # Comma-delimited list of `<field>:<direction>` pairs that define the sort order
  config :sort, :validate => :string, :default => "@timestamp:desc"

  # Array of fields to copy from old event (found via elasticsearch) into new event
  config :fields, :validate => :array, :default => {}

  # Custom headers for Elasticsearch requests
  config :custom_headers, :validate => :hash, :default => {}

  # Hash of docinfo fields to copy from old event (found via elasticsearch) into new event
  config :docinfo_fields, :validate => :hash, :default => {}

  # Hash of aggregation names to copy from elasticsearch response into Logstash event fields
  config :aggregation_fields, :validate => :hash, :default => {}

  # Basic Auth - username
  config :user, :validate => :string

  # Basic Auth - password
  config :password, :validate => :password

  # Cloud ID, from the Elastic Cloud web console. If set `hosts` should not be used.
  #
  # For more info, check out the https://www.elastic.co/guide/en/logstash/current/connecting-to-cloud.html#_cloud_id[Logstash-to-Cloud documentation]
  config :cloud_id, :validate => :string

  # Cloud authentication string ("<username>:<password>" format) is an alternative for the `user`/`password` configuration.
  #
  # For more info, check out the https://www.elastic.co/guide/en/logstash/current/connecting-to-cloud.html#_cloud_auth[Logstash-to-Cloud documentation]
  config :cloud_auth, :validate => :password

  # Authenticate using Elasticsearch API key.
  # format is id:api_key (as returned by https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html[Create API key])
  config :api_key, :validate => :password

  # Set the address of a forward HTTP proxy.
  config :proxy, :validate => :uri_or_empty


  # OpenSSL-style X.509 certificate certificate to authenticate the client
  config :ssl_certificate, :validate => :path

  # SSL Certificate Authority files in PEM encoded format, must also include any chain certificates as necessary
  config :ssl_certificate_authorities, :validate => :path, :list => true

  # The list of cipher suites to use, listed by priorities.
  # Supported cipher suites vary depending on which version of Java is used.
  config :ssl_cipher_suites, :validate => :string, :list => true

  # SSL
  config :ssl_enabled, :validate => :boolean

  # OpenSSL-style RSA private key to authenticate the client
  config :ssl_key, :validate => :path

  # Set the keystore password
  config :ssl_keystore_password, :validate => :password

  # The keystore used to present a certificate to the server.
  # It can be either .jks or .p12
  config :ssl_keystore_path, :validate => :path

  # The format of the keystore file. It must be either jks or pkcs12
  config :ssl_keystore_type, :validate => %w[pkcs12 jks]

  # Supported protocols with versions.
  config :ssl_supported_protocols, :validate => %w[TLSv1.1 TLSv1.2 TLSv1.3], :default => [], :list => true

  # Set the truststore password
  config :ssl_truststore_password, :validate => :password

  # The JKS truststore to validate the server's certificate.
  # Use either `:ssl_truststore_path` or `:ssl_certificate_authorities`
  config :ssl_truststore_path, :validate => :path

  # The format of the truststore file. It must be either jks or pkcs12
  config :ssl_truststore_type, :validate => %w[pkcs12 jks]

  # Options to verify the server's certificate.
  # "full": validates that the provided certificate has an issue date that’s within the not_before and not_after dates;
  # chains to a trusted Certificate Authority (CA); has a hostname or IP address that matches the names within the certificate.
  # "none": performs no certificate validation. Disabling this severely compromises security (https://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf)
  config :ssl_verification_mode, :validate => %w[full none], :default => 'full'

  # Whether results should be sorted or not
  config :enable_sort, :validate => :boolean, :default => true

  # How many results to return
  config :result_size, :validate => :number, :default => 1

  # Tags the event on failure to look up geo information. This can be used in later analysis.
  config :tag_on_failure, :validate => :array, :default => ["_elasticsearch_lookup_failure"]

  # If set, the the result set will be nested under the target field
  config :target, :validate => :field_reference

  # How many times to retry on failure?
  config :retry_on_failure, :validate => :number, :default => 0

  # What status codes to retry on?
  config :retry_on_status, :validate => :number, :list => true, :default => [500, 502, 503, 504]

  # named placeholders in ES|QL query
  # example,
  #   if the query is "FROM my-index | WHERE some_type = ?type"
  #   named placeholders can be applied as the following in query_params:
  #   query_params => {
  #     "type" => "%{[type]}"
  #   }
  config :query_params, :validate => :hash, :default => {}

  config :ssl, :obsolete => "Set 'ssl_enabled' instead."
  config :ca_file, :obsolete => "Set 'ssl_certificate_authorities' instead."
  config :keystore, :obsolete => "Set 'ssl_keystore_path' instead."
  config :keystore_password, :validate => :password, :obsolete => "Set 'ssl_keystore_password' instead."

  # config :ca_trusted_fingerprint, :validate => :sha_256_hex
  include LogStash::PluginMixins::CATrustedFingerprintSupport

  include MonitorMixin
  attr_reader :shared_client

  LS_ESQL_SUPPORT_VERSION = "8.17.4" # the version started using elasticsearch-ruby v8
  ES_ESQL_SUPPORT_VERSION = "8.11.0"

  ##
  # @override to handle proxy => '' as if none was set
  # @param value [Array<Object>]
  # @param validator [nil,Array,Symbol]
  # @return [Array(true,Object)]: if validation is a success, a tuple containing `true` and the coerced value
  # @return [Array(false,String)]: if validation is a failure, a tuple containing `false` and the failure reason.
  def self.validate_value(value, validator)
    return super unless validator == :uri_or_empty

    value = deep_replace(value)
    value = hash_or_array(value)

    return true, value.first if value.size == 1 && value.first.empty?

    return super(value, :uri)
  end

  attr_reader :query_dsl

  def register
    case @query_type
    when "esql"
      invalid_params_with_esql = original_params.keys & %w(index query_template sort docinfo_fields aggregation_fields enable_sort result_size)
      raise LogStash::ConfigurationError, "Configured #{invalid_params_with_esql} params cannot be used with ES|QL query" if invalid_params_with_esql.any?

      validate_ls_version_for_esql_support!
      validate_esql_query_and_params!
      @esql_executor ||= LogStash::Filters::Elasticsearch::EsqlExecutor.new(self, @logger)
    else # dsl
      validate_dsl_query_settings!
      @esql_executor ||= LogStash::Filters::Elasticsearch::DslExecutor.new(self, @logger)
    end

    fill_hosts_from_cloud_id
    setup_ssl_params!
    validate_authentication
    fill_user_password_from_cloud_auth

    @hosts = Array(@hosts).map { |host| host.to_s } # potential SafeURI#to_s

    test_connection!
    validate_es_for_esql_support! if @query_type == "esql"
    setup_serverless
    if get_client.es_transport_client_type == "elasticsearch_transport"
      require_relative "elasticsearch/patches/_elasticsearch_transport_http_manticore"
    end
  end # def register

  def filter(event)
    @esql_executor.process(get_client, event)
  end # def filter

  def decorate(event)
    # this Elasticsearch class has access to `filter_matched`
    filter_matched(event)
  end

  # public only to be reused in testing
  def prepare_user_agent
    os_name = java.lang.System.getProperty('os.name')
    os_version = java.lang.System.getProperty('os.version')
    os_arch = java.lang.System.getProperty('os.arch')
    jvm_vendor = java.lang.System.getProperty('java.vendor')
    jvm_version = java.lang.System.getProperty('java.version')

    plugin_version = Gem.loaded_specs['logstash-filter-elasticsearch'].version
    # example: logstash/7.14.1 (OS=Linux-5.4.0-84-generic-amd64; JVM=AdoptOpenJDK-11.0.11) logstash-output-elasticsearch/11.0.1
    "logstash/#{LOGSTASH_VERSION} (OS=#{os_name}-#{os_version}-#{os_arch}; JVM=#{jvm_vendor}-#{jvm_version}) logstash-#{@plugin_type}-#{config_name}/#{plugin_version}"
  end

  private

  def client_options
    @client_options ||= {
      :user => @user,
      :password => @password,
      :api_key => @api_key,
      :proxy => @proxy,
      :ssl => client_ssl_options,
      :retry_on_failure => @retry_on_failure,
      :retry_on_status => @retry_on_status,
      :user_agent => prepare_user_agent,
      :custom_headers => @custom_headers
    }
  end

  def client_ssl_options
    ssl_options = {}
    ssl_options[:enabled] = @ssl_enabled

    # If the deprecated `ssl` option was explicitly provided, it keeps the same behavior
    # setting up all the client SSL configs even if ssl => false. Otherwise, it should use
    # the @ssl_enabled value as it was either explicitly set by the `ssl_enabled` option or
    # inferred from the hosts scheme.
    return ssl_options unless @ssl_enabled || original_params.include?('ssl')

    ssl_options[:enabled] = true
    ssl_certificate_authorities, ssl_truststore_path, ssl_certificate, ssl_keystore_path = params.values_at('ssl_certificate_authorities', 'ssl_truststore_path', 'ssl_certificate', 'ssl_keystore_path')

    if ssl_certificate_authorities && ssl_truststore_path
      raise LogStash::ConfigurationError, 'Use either "ssl_certificate_authorities/ca_file" or "ssl_truststore_path" when configuring the CA certificate'
    end

    if ssl_certificate && ssl_keystore_path
      raise LogStash::ConfigurationError, 'Use either "ssl_certificate" or "ssl_keystore_path/keystore" when configuring client certificates'
    end

    if ssl_certificate_authorities&.any?
      raise LogStash::ConfigurationError, 'Multiple values on "ssl_certificate_authorities" are not supported by this plugin' if ssl_certificate_authorities.size > 1
      ssl_options[:ca_file] = ssl_certificate_authorities.first
    end

    setup_client_ssl_store(ssl_options, 'truststore', ssl_truststore_path)
    setup_client_ssl_store(ssl_options, 'keystore', ssl_keystore_path)
    logger.debug("Keystore for client certificate", :keystore => ssl_keystore_path) if ssl_keystore_path

    ssl_key = params["ssl_key"]
    if ssl_certificate
      raise LogStash::ConfigurationError, 'Using an "ssl_certificate" requires an "ssl_key"' unless ssl_key
      ssl_options[:client_cert] = ssl_certificate
      ssl_options[:client_key] = ssl_key
    elsif !ssl_key.nil?
      raise LogStash::ConfigurationError, 'An "ssl_certificate" is required when using an "ssl_key"'
    end

    ssl_verification_mode = params["ssl_verification_mode"]
    unless ssl_verification_mode.nil?
      case ssl_verification_mode
        when 'none'
          logger.warn "You have enabled encryption but DISABLED certificate verification, " +
                        "to make sure your data is secure set `ssl_verification_mode => full`"
          ssl_options[:verify] = :disable
        else
          # Manticore's :default maps to Apache HTTP Client's DefaultHostnameVerifier,
          # which is the modern STRICT verifier that replaces the deprecated StrictHostnameVerifier
          ssl_options[:verify] = :default
      end
    end

    ssl_options[:cipher_suites] = params["ssl_cipher_suites"] if params.include?("ssl_cipher_suites")
    protocols = params['ssl_supported_protocols']
    ssl_options[:protocols] = protocols if protocols&.any?
    ssl_options[:trust_strategy] = trust_strategy_for_ca_trusted_fingerprint

    ssl_options
  end

  # @param kind is a string [truststore|keystore]
  def setup_client_ssl_store(ssl_options, kind, store_path)
    if store_path
      ssl_options[kind.to_sym] = store_path
      ssl_options["#{kind}_type".to_sym] = params["ssl_#{kind}_type"] if params.include?("ssl_#{kind}_type")
      ssl_options["#{kind}_password".to_sym] = params["ssl_#{kind}_password"].value if params.include?("ssl_#{kind}_password")
    end
  end

  def new_client
    # NOTE: could pass cloud-id/cloud-auth to client but than we would need to be stricter on ES version requirement
    # and also LS parsing might differ from ES client's parsing so for consistency we do not pass cloud options ...
    LogStash::Filters::ElasticsearchClient.new(@logger, @hosts, client_options)
  end

  def get_client
    @shared_client || synchronize do
      @shared_client ||= new_client
    end
  end

  def hosts_default?(hosts)
    hosts.is_a?(Array) && hosts.size == 1 && !original_params.key?('hosts')
  end

  def validate_authentication
    authn_options = 0
    authn_options += 1 if @cloud_auth
    authn_options += 1 if (@api_key && @api_key.value)
    authn_options += 1 if (@user || (@password && @password.value))

    if authn_options > 1
      raise LogStash::ConfigurationError, 'Multiple authentication options are specified, please only use one of user/password, cloud_auth or api_key'
    end

    if @api_key && @api_key.value && @ssl_enabled != true
      raise(LogStash::ConfigurationError, "Using api_key authentication requires SSL/TLS secured communication using the `ssl => true` option")
    end
  end

  def fill_user_password_from_cloud_auth
    return unless @cloud_auth

    @user, @password = parse_user_password_from_cloud_auth(@cloud_auth)
    params['user'], params['password'] = @user, @password
  end

  def fill_hosts_from_cloud_id
    return unless @cloud_id

    if @hosts && !hosts_default?(@hosts)
      raise LogStash::ConfigurationError, 'Both cloud_id and hosts specified, please only use one of those.'
    end
    @hosts = parse_host_uri_from_cloud_id(@cloud_id)
  end

  def parse_host_uri_from_cloud_id(cloud_id)
    require 'logstash/util/safe_uri'
    begin # might not be available on older LS
      require 'logstash/util/cloud_setting_id'
    rescue LoadError
      raise LogStash::ConfigurationError, 'The cloud_id setting is not supported by your version of Logstash, ' +
          'please upgrade your installation (or set hosts instead).'
    end

    begin
      cloud_id = LogStash::Util::CloudSettingId.new(cloud_id) # already does append ':{port}' to host
    rescue ArgumentError => e
      raise LogStash::ConfigurationError, e.message.to_s.sub(/Cloud Id/i, 'cloud_id')
    end
    cloud_uri = "#{cloud_id.elasticsearch_scheme}://#{cloud_id.elasticsearch_host}"
    LogStash::Util::SafeURI.new(cloud_uri)
  end

  def parse_user_password_from_cloud_auth(cloud_auth)
    begin # might not be available on older LS
      require 'logstash/util/cloud_setting_auth'
    rescue LoadError
      raise LogStash::ConfigurationError, 'The cloud_auth setting is not supported by your version of Logstash, ' +
          'please upgrade your installation (or set user/password instead).'
    end

    cloud_auth = cloud_auth.value if cloud_auth.is_a?(LogStash::Util::Password)
    begin
      cloud_auth = LogStash::Util::CloudSettingAuth.new(cloud_auth)
    rescue ArgumentError => e
      raise LogStash::ConfigurationError, e.message.to_s.sub(/Cloud Auth/i, 'cloud_auth')
    end
    [ cloud_auth.username, cloud_auth.password ]
  end

  def test_connection!
    begin
      get_client.client.ping
    rescue Elasticsearch::UnsupportedProductError
      raise LogStash::ConfigurationError, "Could not connect to a compatible version of Elasticsearch"
    end
  end

  def setup_serverless
    if get_client.serverless?
      @client_options[:serverless] = true
      @shared_client = new_client
      get_client.info
    end
  rescue => e
    @logger.error("Failed to retrieve Elasticsearch info", message: e.message, exception: e.class, backtrace: e.backtrace)
    raise LogStash::ConfigurationError, "Could not connect to a compatible version of Elasticsearch"
  end

  def setup_ssl_params!
    # Infer the value if neither `ssl_enabled` was not set
    return if original_params.include?('ssl_enabled')
    params['ssl_enabled'] = @ssl_enabled ||= Array(@hosts).all? { |host| host && host.to_s.start_with?("https") }
  end

  def validate_dsl_query_settings!
    #Load query if it exists
    if @query_template
      if File.zero?(@query_template)
        raise "template is empty"
      end
      file = File.open(@query_template, 'r')
      @query_dsl = file.read
    end

    validate_query_settings
  end

  def validate_query_settings
    unless @query || @query_template
      raise LogStash::ConfigurationError, "Both `query` and `query_template` are empty. Require either `query` or `query_template`."
    end

    if @query && @query_template
      raise LogStash::ConfigurationError, "Both `query` and `query_template` are set. Use either `query` or `query_template`."
    end

    if original_params.keys.include?("query_params")
      raise LogStash::ConfigurationError, "`query_params` is not allowed when `query_type => 'dsl'`."
    end
  end

  def validate_ls_version_for_esql_support!
    if Gem::Version.create(LOGSTASH_VERSION) < Gem::Version.create(LS_ESQL_SUPPORT_VERSION)
      fail("Current version of Logstash does not include Elasticsearch client which supports ES|QL. Please upgrade Logstash to at least #{LS_ESQL_SUPPORT_VERSION}")
    end
  end

  def validate_esql_query_and_params!
    illegal_keys = @query_params.keys.reject {|k| k[/^[a-z_][a-z0-9_]*$/] }
    raise LogStash::ConfigurationError, "Illegal #{illegal_keys} placeholder names in `query_params`" if illegal_keys.any?

    placeholders = @query.scan(/(?<=[?])[a-z_][a-z0-9_]*/i)
    placeholders.each do |placeholder|
      raise LogStash::ConfigurationError, "Placeholder #{placeholder} not found in query" unless @query_params.include?(placeholder)
    end
  end

  def validate_es_for_esql_support!
    # make sure connected ES supports ES|QL (8.11+)
    @es_version ||= get_client.es_version
    es_supports_esql = Gem::Version.create(@es_version) >= Gem::Version.create(ES_ESQL_SUPPORT_VERSION)
    fail("Connected Elasticsearch #{@es_version} version does not supports ES|QL. ES|QL feature requires at least Elasticsearch #{ES_ESQL_SUPPORT_VERSION} version.") unless es_supports_esql
  end

end #class LogStash::Filters::Elasticsearch
