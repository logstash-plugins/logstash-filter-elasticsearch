# encoding: utf-8

module LogStash
  module Filters
    class Elasticsearch
      class EsqlExecutor

        def initialize(plugin, logger)
          @plugin = plugin

          params = plugin.params["query_params"] || {}
          @drop_null_columns = params["drop_null_columns"] || false
          @named_params = params["named_params"] || []
          @query = plugin.params["query"]
          @fields = plugin.params["fields"]
          @tag_on_failure = plugin.params["tag_on_failure"]
          @logger = logger
        end

        def process(client, event)
          resolved_params = @named_params&.any? ? resolve_parameters(event) : []
          response = execute_query(client, resolved_params)
          inform_warning(response)
          process_response(event, response)
          @plugin.decorate(event)
        rescue => e
          @logger.error("Failed to process ES|QL filter", exception: e)
          @tag_on_failure.each { |tag| event.tag(tag) }
        end

        private

        def resolve_parameters(event)
          @named_params.map do |entry|
            entry.each_with_object({}) do |(key, value), new_entry|
              begin
                new_entry[key] = event.sprintf(value)
              rescue => e
                @logger.error("Failed to resolve parameter", key: key, value: value, error: e.message)
                raise
              end
            end
          end
        end

        def execute_query(client, params)
          @logger.debug("Executing ES|QL query", query: @query, params: params)
          client.search({ body: { query: @query, params: params }, format: 'json', drop_null_columns: @drop_null_columns }, 'esql')
        end

        def process_response(event, response)
          return unless response['values'] && response['columns']

          # TODO: set to the target field once target support is added
          event.set("[@metadata][total_values]", response['values'].size)
          add_requested_fields(event, response)
        end

        def inform_warning(response)
          return unless (warning = response&.headers&.dig('warning'))
          @logger.warn("ES|QL executor received warning", { message: warning })
        end

        def add_requested_fields(event, response)
          @fields.each do |old_key, new_key|
            column_index = response['columns'].find_index { |col| col['name'] == old_key }
            next unless column_index

            values = response['values'].map { |entry| entry[column_index] }
            event.set(new_key, values.one? ? values.first : values) if values&.size > 0
          end
        end
      end
    end
  end
end
