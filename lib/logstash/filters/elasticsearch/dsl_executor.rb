# encoding: utf-8

module LogStash
  module Filters
    class Elasticsearch
      class DslExecutor
        def initialize(plugin, logger)
          @plugin = plugin
          @index = plugin.params["index"]
          @query = plugin.params["query"]
          @query_dsl = plugin.query_dsl
          @fields = plugin.params["fields"]
          @result_size = plugin.params["result_size"]
          @docinfo_fields = plugin.params["docinfo_fields"]
          @tag_on_failure = plugin.params["tag_on_failure"]
          @enable_sort = plugin.params["enable_sort"]
          @sort = plugin.params["sort"]
          @aggregation_fields = plugin.params["aggregation_fields"]
          @logger = logger
        end

        def process(client, event)
          matched = false
          begin
            params = { :index => event.sprintf(@index) }

            if @query_dsl
              query = LogStash::Json.load(event.sprintf(@query_dsl))
              params[:body] = query
            else
              query = event.sprintf(@query)
              params[:q] = query
              params[:size] = @result_size
              params[:sort] = @sort if @enable_sort
            end

            @logger.debug("Querying elasticsearch for lookup", :params => params)

            results = client.search(params)
            raise "Elasticsearch query error: #{results["_shards"]["failures"]}" if results["_shards"].include? "failures"

            event.set("[@metadata][total_hits]", extract_total_from_hits(results['hits']))

            result_hits = results["hits"]["hits"]
            if !result_hits.nil? && !result_hits.empty?
              matched = true
              @fields.each do |old_key, new_key|
                old_key_path = extract_path(old_key)
                set = result_hits.map do |doc|
                  extract_value(doc["_source"], old_key_path)
                end
                event.set(new_key, set.count > 1 ? set : set.first)
              end
              @docinfo_fields.each do |old_key, new_key|
                old_key_path = extract_path(old_key)
                set = result_hits.map do |doc|
                  extract_value(doc, old_key_path)
                end
                event.set(new_key, set.count > 1 ? set : set.first)
              end
            end

            result_aggregations = results["aggregations"]
            if !result_aggregations.nil? && !result_aggregations.empty?
              matched = true
              @aggregation_fields.each do |agg_name, ls_field|
                event.set(ls_field, result_aggregations[agg_name])
              end
            end

          rescue => e
            if @logger.trace?
              @logger.warn("Failed to query elasticsearch for previous event", :index => @index, :query => @query, :event => event.to_hash, :error => e.message, :backtrace => e.backtrace)
            elsif @logger.debug?
              @logger.warn("Failed to query elasticsearch for previous event", :index => @index, :error => e.message, :backtrace => e.backtrace)
            else
              @logger.warn("Failed to query elasticsearch for previous event", :index => @index, :error => e.message)
            end
            @tag_on_failure.each { |tag| event.tag(tag) }
          else
            @plugin.decorate(event) if matched
          end
        end

        private

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

      end
    end
  end
end