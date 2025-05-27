# encoding: utf-8

module LogStash
  module Filters
    class Elasticsearch
      class EsqlExecutor

        def initialize(plugin, logger)
          @logger = logger

          @event_decorator = plugin.method(:decorate)
          @query = plugin.params["query"]
          unless @query.match?(/\|\s*LIMIT/)
            @logger.warn("ES|QL query doesn't contain LIMIT, adding `| LIMIT 1` to optimize the performance")
            @query.concat(' | LIMIT 1')
          end

          @query_params = plugin.params["query_params"] || {}

          @fields = plugin.params["fields"]
          @tag_on_failure = plugin.params["tag_on_failure"]
          @logger.debug("ES|QL query executor initialized with ", query: @query, query_params: @query_params)

          @target_field = plugin.params["target"]
          if @target_field
            def self.apply_target(path); "[#{@target_field}][#{path}]"; end
          else
            def self.apply_target(path); path; end
          end
        end

        def process(client, event)
          resolved_params = @query_params&.any? ? resolve_parameters(event) : []
          response = execute_query(client, resolved_params)
          inform_warning(response)
          process_response(event, response)
          @event_decorator.call(event)
        rescue => e
          @logger.error("Failed to process ES|QL filter", exception: e)
          @tag_on_failure.each { |tag| event.tag(tag) }
        end

        private

        def resolve_parameters(event)
          @query_params.each_with_object([]) do |(key, value), resolved_parameters|
            begin
              resolved_value = event.get(value)
              @logger.debug("Resolved value for #{key}: #{resolved_value}, its class: #{resolved_value.class}")
              resolved_parameters << { key => resolved_value } if resolved_value
            rescue => e
              # catches invalid field reference
              @logger.error("Failed to resolve parameter", key: key, value: value, error: e.message)
              raise
            end
          end
        end

        def execute_query(client, params)
          # debug logs may help to check what query shape the plugin is sending to ES
          @logger.debug("Executing ES|QL query", query: @query, params: params)
          client.esql_query({ body: { query: @query, params: params }, format: 'json', drop_null_columns: true })
        end

        def process_response(event, response)
          columns = response['columns']&.freeze || []
          values = response['values']&.freeze || []
          if values.nil? || values.size == 0
            @logger.debug("Empty ES|QL query result", columns: columns, values: values)
            return
          end

          # this shouldn't happen but just in case not crash the plugin
          if columns.nil? || columns.size == 0
            @logger.error("No columns exist but received values", columns: columns, values: values)
            return
          end

          event.set("[@metadata][total_values]", values.size)
          # @logger.debug("Executing ES|QL values size ", values.size)
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

            row_values = values.map { |entry| entry[column_index] }&.compact
            value_to_set = row_values.count > 1 ? row_values : row_values.first
            set_to_event_target(event, new_key, value_to_set) unless value_to_set.nil?
          end
        end

        # if @target is defined, creates a nested structure to inject a result into the target field
        # if not defined, directly sets to the top-level event field
        # @param event [LogStash::Event]
        # @param new_key [String] name of the field to set
        # @param value_to_set [Array] values to set
        # @return [void]
        def set_to_event_target(event, new_key, value_to_set)
          key_to_set = self.apply_target(new_key)
          event.set(key_to_set, value_to_set)
        end
      end
    end
  end
end
