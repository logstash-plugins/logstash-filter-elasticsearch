# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require_relative "elasticsearch/client"


# Search elasticsearch for a previous log event and copy some fields from it
# into the current event.  Below is a complete example of how this filter might
# be used.  Whenever logstash receives an "end" event, it uses this elasticsearch
# filter to find the matching "start" event based on some operation identifier.
# Then it copies the `@timestamp` field from the "start" event into a new field on
# the "end" event.  Finally, using a combination of the "date" filter and the
# "ruby" filter, we calculate the time duration in hours between the two events.
# [source,ruby]
#       if [type] == "end" {
#          elasticsearch {
#             hosts => ["es-server"]
#             query => "type:start AND operation:%{[opid]}"
#             fields => [["@timestamp", "started"]]
#          }
#
#          date {
#             match => ["[started]", "ISO8601"]
#             target => "[started]"
#          }
#
#          ruby {
#             code => "event['duration_hrs'] = (event['@timestamp'] - event['started']) / 3600 rescue nil"
#          }
#       }
#
class LogStash::Filters::Elasticsearch < LogStash::Filters::Base
  config_name "elasticsearch"

  # List of elasticsearch hosts to use for querying.
  config :hosts, :validate => :array,  :default => [ "localhost:9200" ]
  
  # Comma-delimited list of index names to search; use `_all` or empty string to perform the operation on all indices
  config :index, :validate => :string, :default => ""

  # Elasticsearch query string. Read the Elasticsearch query string documentation
  # for more info at: https://www.elastic.co/guide/en/elasticsearch/reference/master/query-dsl-query-string-query.html#query-string-syntax
  config :query, :validate => :string

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

  def register
    options = {
      :ssl => @ssl,
      :hosts => @hosts,
      :ca_file => @ca_file,
      :logger => @logger
    }
    @client = LogStash::Filters::ElasticsearchClient.new(@user, @password, options)
  end # def register

  def filter(event)
    begin
      query_str = event.sprintf(@query)

      params = { :q => query_str, :size => result_size, :index => @index }
      params[:sort] =  @sort if @enable_sort
      results = @client.search(params)

      @fields.each do |old_key, new_key|
        if !results['hits']['hits'].empty?
          set = []
          results["hits"]["hits"].to_a.each do |doc|
            set << doc["_source"][old_key]
          end
          event[new_key] = ( set.count > 1 ? set : set.first)
        end
      end
    rescue => e
      @logger.warn("Failed to query elasticsearch for previous event", :index => @index, :query => query_str, :event => event, :error => e)
      @tag_on_failure.each{|tag| event.tag(tag)}
    end
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Elasticsearch
