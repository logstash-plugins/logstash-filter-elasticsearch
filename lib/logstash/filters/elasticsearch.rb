# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require_relative "elasticsearch/client"
require "logstash/json"
java_import "java.util.concurrent.ConcurrentHashMap"

# .Compatibility Note
# [NOTE]
# ================================================================================
# Starting with Elasticsearch 5.3, there's an {ref}modules-http.html[HTTP setting]
# called `http.content_type.required`. If this option is set to `true`, and you
# are using Logstash 2.4 through 5.2, you need to update the Elasticsearch filter
# plugin to version 3.1.1 or higher.
# 
# ================================================================================
# 
# Search Elasticsearch for a previous log event and copy some fields from it
# into the current event.  Below are two complete examples of how this filter might
# be used.
#
# The first example uses the legacy 'query' parameter where the user is limited to an Elasticsearch query_string.
# Whenever logstash receives an "end" event, it uses this elasticsearch
# filter to find the matching "start" event based on some operation identifier.
# Then it copies the `@timestamp` field from the "start" event into a new field on
# the "end" event.  Finally, using a combination of the "date" filter and the
# "ruby" filter, we calculate the time duration in hours between the two events.
# [source,ruby]
# --------------------------------------------------
#       if [type] == "end" {
#          elasticsearch {
#             hosts => ["es-server"]
#             query => "type:start AND operation:%{[opid]}"
#             fields => { "@timestamp" => "started" }
#          }
#
#          date {
#             match => ["[started]", "ISO8601"]
#             target => "[started]"
#          }
#
#          ruby {
#             code => "event.set('duration_hrs', (event.get('@timestamp') - event.get('started')) / 3600) rescue nil"
#          }
#       }
#
#  The example below reproduces the above example but utilises the query_template.  This query_template represents a full
#  Elasticsearch query DSL and supports the standard Logstash field substitution syntax.  The example below issues
#  the same query as the first example but uses the template shown.
#
#   if [type] == "end" {
#          elasticsearch {
#             hosts => ["es-server"]
#             query_template => "template.json"
#          }
#
#          date {
#             match => ["started", "ISO8601"]
#             target => "started"
#          }
#
#          ruby {
#             code => "event.set('duration_hrs', (event.get('@timestamp') - event.get('started')) / 3600) rescue nil"
#          }
#   }
#
#
#
#   template.json:
#
#  {
#     "query": {
#       "query_string": {
#        "query": "type:start AND operation:%{[opid]}"
#       }
#     },
#    "_source": ["@timestamp", "started"]
#  }
#
# As illustrated above, through the use of 'opid', fields from the Logstash events can be referenced within the template.
# The template will be populated per event prior to being used to query Elasticsearch.
#
# --------------------------------------------------

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

  end # def register

  def filter(event)
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
      @fields.each do |old_key, new_key|
        if !results['hits']['hits'].empty?
          set = []
          results["hits"]["hits"].to_a.each do |doc|
            set << doc["_source"][old_key]
          end
          event.set(new_key, set.count > 1 ? set : set.first)
        end
      end
    rescue => e
      @logger.warn("Failed to query elasticsearch for previous event", :index => @index, :query => query, :event => event, :error => e)
      @tag_on_failure.each{|tag| event.tag(tag)}
    end
    filter_matched(event)
  end # def filter

  private
  def client_options
    {
      :ssl => @ssl,
      :hosts => @hosts,
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
end #class LogStash::Filters::Elasticsearch
