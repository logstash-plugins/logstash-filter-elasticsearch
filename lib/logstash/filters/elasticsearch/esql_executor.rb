# encoding: utf-8

module LogStash
  module Filters
    class Elasticsearch
      class EsqlExecutor

        def initialize(plugin, logger)
          @plugin = plugin
          @logger = logger

          @query = plugin.params["query"]
          if @query.strip.start_with?("FROM") && !@query.match?(/\|\s*LIMIT/)
            @logger.warn("ES|QL query doesn't contain LIMIT, adding `| LIMIT 1` to optimize the performance")
            @query.concat(' | LIMIT 1')
          end

          query_params = plugin.params["query_params"] || {}
          @named_params = query_params["named_params"] || []
          @fields = plugin.params["fields"]
          @tag_on_failure = plugin.params["tag_on_failure"]
          @logger.debug("ES|QL query executor initialized with ", query: @query, named_params: @named_params)
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
                resolved_value = event.get(value)
                @logger.debug("Resolved value for #{key}: #{resolved_value}, its class: #{resolved_value.class}")
                new_entry[key] = resolved_value
              rescue => e
                # catches invalid field reference
                @logger.error("Failed to resolve parameter", key: key, value: value, error: e.message)
                raise
              end
            end
          end
        end

        def execute_query(client, params)
          # debug logs  may help to check what query shape the plugin is sending to ES
          @logger.debug("Executing ES|QL query", query: @query, params: params)
          client.search({ body: { query: @query, params: params }, format: 'json', drop_null_columns: true }, 'esql')
        end

        def process_response(event, response)
          columns = response['columns'].freeze
          values = response['values'].freeze
          if values.nil? || values.size == 0
            @logger.debug("Empty ES|QL query result", columns: columns, values: values)
            return
          end

          # this shouldn't never happen but just in case not crash the plugin
          if columns.nil? || columns.size == 0
            @logger.error("No columns exist but received values", columns: columns, values: values)
            return
          end

          # TODO: do we need to set `total_hits` to target?
          #   if not, how do we resolve conflict with existing es-input total_hits field?
          #   FYI: with DSL it stores in `[@metadata][total_hits]`
          event.set("[@metadata][total_hits]", values.size)
          add_requested_fields(event, columns, values)
        end

        def inform_warning(response)
          return unless (warning = response&.headers&.dig('warning'))
          @logger.warn("ES|QL executor received warning", { message: warning })
        end

        def add_requested_fields(event, columns, values)
          @fields.each do |old_key, new_key|
            column_index = columns.find_index { |col| col['name'] == old_key }
            next unless column_index

            row_values = values[column_index]&.compact # remove non-exist field values with compact
            # TODO: set to the target field once target support is added
            event.set(new_key, row_values.one? ? row_values.first : row_values) if row_values&.size > 0
          end
        end
      end
    end
  end
end
