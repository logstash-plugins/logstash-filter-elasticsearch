require "logstash/filters/base"
require "logstash/namespace"
require "base64"
require "uri"


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
  config :hosts, :validate => :array, :default => [ "localhost:9200" ]
  
  # Use transport_options to provide advanced options to underlying trasnport Library (Faraday)
  config :transport_options, :validate => :hash, :default => {}  

  # Comma-delimited list of index names to search; use `_all` or empty string to perform the operation on all indices
  config :index, :validate => :string, :default => ""

  # Elasticsearch query string
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


  public
  def register
    require "elasticsearch"

    transport_options = @transport_options

    hosts = @hosts.map do |host| 
        host_parts = case host
          when String   
            if host =~ /^[a-z]+\:\/\//
              uri = URI.parse(host)
              { :scheme => uri.scheme, :user => uri.user, :password => uri.password, :host => uri.host, :path => uri.path, :port => uri.port }
            else
              host, port = host.split(':')
              { :host => host, :port => port }
            end
          when URI
            { :scheme => host.scheme, :user => host.user, :password => host.password, :host => host.host, :path => host.path, :port => host.port }
          when Hash
            host
          else
            raise ArgumentError, "Please pass host as a String, URI or Hash -- #{host.class} given."
          end

        if host_parts[:port].nil?
          host_parts[:port]=9200
        else
         host_parts[:port] = host_parts[:port].to_i
        end
        
        if @ssl 
            host_parts[:scheme] = 'https'
        end

        if @user && @password
          if host_parts[:user].nil?
            host_parts[:user] = @user
          end
          if host_parts[:password].nil?
            host_parts[:password]  = @password.value
          end
        end

        host_parts
      end
    
    if @ssl && @ca_file
      transport_options[:ssl] = { ca_file: @ca_file }
    end

    @logger.info("New ElasticSearch filter", :hosts => hosts)
    @client = Elasticsearch::Client.new hosts: hosts, transport_options: transport_options
  end # def register

  public
  def filter(event)
    

    begin
      query_str = event.sprintf(@query)

      results = @client.search index: @index, q: query_str, sort: @sort, size: 1

      @fields.each do |old, new|
        event[new] = results['hits']['hits'][0]['_source'][old]
      end

      filter_matched(event)
    rescue => e
      @logger.warn("Failed to query elasticsearch for previous event",
                   :index => index, :query => query_str, :event => event, :error => e)
    end
  end # def filter
end # class LogStash::Filters::Elasticsearch
