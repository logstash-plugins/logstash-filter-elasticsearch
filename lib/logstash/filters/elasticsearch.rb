# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require_relative "elasticsearch/client"
require "logstash/json"
java_import "java.util.concurrent.ConcurrentHashMap"

require 'resolv'


class LogStash::Filters::Elasticsearch < LogStash::Filters::Base
  config_name "elasticsearch"

  # List of elasticsearch hosts to use for querying.
  config :hosts, :validate => :array,  :default => [ "localhost:9200" ]
  
  # Comma-delimited list of index names to search; use `_all` or empty string to perform the operation on all indices.
  # Field substitution (e.g. `index-name-%{date_field}`) is available
  config :index, :validate => :string, :default => ""

  # Elasticsearch query string. Read the Elasticsearch query string documentation.
  # for more info at: https://www.elastic.co/guide/en/elasticsearch/reference/master/query-dsl-query-string-query.html#query-string-syntax
  config :query, :validate => :string

  # File path to elasticsearch query in DSL format. Read the Elasticsearch query documentation
  # for more info at: https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html
  config :query_template, :validate => :string

  # Comma-delimited list of `<field>:<direction>` pairs that define the sort order
  config :sort, :validate => :string, :default => "@timestamp:desc"

  # Array of fields to copy from old event (found via elasticsearch) into new event
  config :fields, :validate => :array, :default => {}

  # Hash of docinfo fields to copy from old event (found via elasticsearch) into new event
  config :docinfo_fields, :validate => :hash, :default => {}

  # Hash of aggregation names to copy from elasticsearch response into Logstash event fields
  config :aggregation_fields, :validate => :hash, :default => {}

  # Basic Auth - username
  config :user, :validate => :string

  # Basic Auth - password
  config :password, :validate => :password

  # SSL
  config :ssl, :validate => :boolean, :default => false

  # SSL Certificate Authority file
  config :ca_file, :validate => :path

  # Whether results should be sorted or not
  config :enable_sort, :validate => :boolean, :default => true

  # How many results to return
  config :result_size, :validate => :number, :default => 1

  # Tags the event on failure to look up geo information. This can be used in later analysis.
  config :tag_on_failure, :validate => :array, :default => ["_elasticsearch_lookup_failure"]

  attr_reader :clients_pool

  def register
    @clients_pool = java.util.concurrent.ConcurrentHashMap.new

    #Load query if it exists
    if @query_template
      if File.zero?(@query_template)
        raise "template is empty"
      end
      file = File.open(@query_template, "rb")
      @query_dsl = file.read
    end

    @normalised_hosts = normalise_hosts(@hosts, @ssl)

    test_connection!
  end # def register

  def filter(event)
    matched = false
    begin
      params = {:index => event.sprintf(@index) }

      if @query_dsl
        query = LogStash::Json.load(event.sprintf(@query_dsl))
        params[:body] = query
      else
        query = event.sprintf(@query)
        params[:q] = query
        params[:size] = result_size
        params[:sort] =  @sort if @enable_sort
      end

      @logger.debug("Querying elasticsearch for lookup", :params => params)

      results = get_client.search(params)
      raise "Elasticsearch query error: #{results["_shards"]["failures"]}" if results["_shards"].include? "failures"

      event.set("[@metadata][total_hits]", extract_total_from_hits(results['hits']))

      resultsHits = results["hits"]["hits"]
      if !resultsHits.nil? && !resultsHits.empty?
        matched = true
        @fields.each do |old_key, new_key|
          old_key_path = extract_path(old_key)
          set = resultsHits.map do |doc|
            extract_value(doc["_source"], old_key_path)
          end
          event.set(new_key, set.count > 1 ? set : set.first)
        end
        @docinfo_fields.each do |old_key, new_key|
          old_key_path = extract_path(old_key)
          set = resultsHits.map do |doc|
            extract_value(doc, old_key_path)
          end
          event.set(new_key, set.count > 1 ? set : set.first)
        end
      end

      resultsAggs = results["aggregations"]
      if !resultsAggs.nil? && !resultsAggs.empty?
        matched = true
        @aggregation_fields.each do |agg_name, ls_field|
          event.set(ls_field, resultsAggs[agg_name])
        end
      end

    rescue => e
      if @logger.trace?
        @logger.warn("Failed to query elasticsearch for previous event", :index => @index, :query => query, :event => event.to_hash, :error => e.message, :backtrace => e.backtrace)
      elsif @logger.debug?
        @logger.warn("Failed to query elasticsearch for previous event", :index => @index, :error => e.message, :backtrace => e.backtrace)
      else
        @logger.warn("Failed to query elasticsearch for previous event", :index => @index, :error => e.message)
      end
      @tag_on_failure.each{|tag| event.tag(tag)}
    else
      filter_matched(event) if matched
    end
  end # def filter

  private
  def client_options
    {
      :hosts => @normalised_hosts,
      :ca_file => @ca_file,
      :logger => @logger
    }
  end

  def new_client
    LogStash::Filters::ElasticsearchClient.new(@user, @password, client_options)
  end

  def get_client
    @clients_pool.computeIfAbsent(Thread.current, lambda { |x| new_client })
  end

  # get an array of path elements from a path reference
  def extract_path(path_reference)
    return [path_reference] unless path_reference.start_with?('[') && path_reference.end_with?(']')

    path_reference[1...-1].split('][')
  end

  # given a Hash and an array of path fragments, returns the value at the path
  # @param source [Hash{String=>Object}]
  # @param path [Array{String}]
  # @return [Object]
  def extract_value(source, path)
    path.reduce(source) do |memo, old_key_fragment|
      break unless memo.include?(old_key_fragment)
      memo[old_key_fragment]
    end
  end

  # Given a "hits" object from an Elasticsearch response, return the total number of hits in
  # the result set.
  # @param hits [Hash{String=>Object}]
  # @return [Integer]
  def extract_total_from_hits(hits)
    total = hits['total']

    # Elasticsearch 7.x produces an object containing `value` and `relation` in order
    # to enable unambiguous reporting when the total is only a lower bound; if we get
    # an object back, return its `value`.
    return total['value'] if total.kind_of?(Hash)

    total
  end

  def test_connection!
    get_client.client.ping
  end

  private

  PATTERN_START_WITH_URI_SCHEME =
    %r{\A[[:alpha:]][[:alnum:]\.\+\-]*://}i

  PATTERN_CAPTURING_HOSTNAME_AND_OPTIONAL_PORT =
    %r{\A([^:\[\]]+|\[[^\]]+\])(?::([0-9]+))?\Z}

  ##
  # Map the provided array-of-strings to an array of `URI::Generic`
  # instances, which the Elasticsearch client can use to establish
  # connections.
  #
  # @param hosts [Array<String>]: (@see `#normalise_host`)
  # @param force_ssl [Boolean]: (@see `#normalise_host`)
  #
  # @return [Array<URI::Generic>]
  def normalise_hosts(hosts, force_ssl)
    hosts.map { |input| normalise_host(input, force_ssl) }
  end

  ##
  # Convert the provided string to a `URI::Generic` instance, which the
  # Elasticsearch client can use to establish connections.
  #
  # @param input [String]: a url, in one of the following formats:
  #                        - a qualified URL with schema, hostname, and
  #                          optional port
  #                        - a bare hostname or ip, optionally followed by a
  #                          colon and port number
  #                        - a square-bracketed ipv6 literal, optionally
  #                          followed by a colon and port number
  #                        - a bare ipv6-address
  # @param force_ssl [Boolean]: true to force SSL; will cause failure if one
  #                             or more hosts explicitly supplies non-SSL
  #                             scheme (e.g., `http`).
  #
  # @return [URI::Generic]
  def normalise_host(input, force_ssl)
    if force_ssl && input.start_with?('http://')
      logger.error("Plugin configured to force SSL with `ssl => true`, " +
                   "but a host explicitly declared non-https URL `#{input}`")

      raise LogStash::ConfigurationError, "Aborting due to conflicting configuration"
    end

    begin
      if PATTERN_START_WITH_URI_SCHEME.match(input)
        # Avoid `URI::parse`, which routes to specific implementations
        # that inject defaults that do not make sense in this context.
        URI::Generic.new(*URI.split(input))
      else
        if PATTERN_CAPTURING_HOSTNAME_AND_OPTIONAL_PORT.match(input)
          host, port = Regexp.last_match.captures
        elsif input =~ Resolv::IPv6::Regex
          # per RFC3986: to be used as hostname in URIs, ipv6 literals
          # MUST be wrapped in square-brackets.
          host, port = "[#{input}]", nil
        else
          fail('unsupported format')
        end
        URI::Generic.new(
          force_ssl ? 'https' : 'http',
          nil, # userinfo,
          host,
          port,
          nil, # registry
          nil, # path
          nil, # opaque
          nil, # query
          nil  # fragment
        )
      end
    rescue => e
      logger.error("Plugin configured with invalid host value `#{input}`",
                   :exception => e.message, :class => e.class.name)
      raise LogStash::ConfigurationError, "Aborting due to invalid configuration"
    end
  end
end #class LogStash::Filters::Elasticsearch
