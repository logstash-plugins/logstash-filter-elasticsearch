# encoding: utf-8

module LogStash
  module Filters
    class Elasticsearch
      class EsqlExecutor

        ESQL_PARSERS_BY_TYPE = Hash.new(lambda { |x| x }).merge(
          'date' => ->(value) { value && LogStash::Timestamp.new(value) },
          )

        def initialize(plugin, logger)
          @logger = logger

          @event_decorator = plugin.method(:decorate)
          @query = plugin.params["query"]

          query_params = plugin.query_params || {}
          reference_valued_params, static_valued_params = query_params.partition { |_, v| v.kind_of?(String) && v.match?(/^\[.*\]$/) }
          @referenced_params = reference_valued_params&.to_h
          # keep static params as an array of hashes to attach to the ES|QL api param easily
          @static_params = static_valued_params.map { |k, v| { k => v } }
          @tag_on_failure = plugin.params["tag_on_failure"]
          @logger.debug("ES|QL query executor initialized with ", query: @query, query_params: query_params)

          # if the target is specified, all result entries will be copied to the target field
          # otherwise, the first value of the result will be copied to the event
          @target_field = plugin.params["target"]
          @logger.warn("Only first query result will be copied to the event. Please specify `target` in plugin config to include all") if @target_field.nil?
        end

        def process(client, event)
          resolved_params = @referenced_params&.any? ? resolve_parameters(event) : []
          resolved_params.concat(@static_params) if @static_params&.any?
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
          @referenced_params.map do |key, value|
            begin
              resolved_value = event.get(value)
              @logger.debug("Resolved value for #{key}: #{resolved_value}, its class: #{resolved_value.class}")
              { key => resolved_value }
            rescue => e
              # catches invalid field reference
              raise "Failed to resolve parameter `#{key}` with `#{value}`. Error: #{e.message}"
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

          # this shouldn't happen but just in case to avoid crashes the plugin
          if columns.nil? || columns.size == 0
            @logger.error("No columns exist but received values", columns: columns, values: values)
            return
          end

          event.set("[@metadata][total_values]", values.size)
          @logger.debug("ES|QL query result values size ", size: values.size)

          column_specs = columns.map { |column| ColumnSpec.new(column) }
          sub_element_mark_map = mark_sub_elements(column_specs)
          multi_fields = sub_element_mark_map.filter_map { |key, val| key.name if val == true }

          @logger.debug("Multi-fields found in ES|QL result and they will not be available in the event. Please use `RENAME` command if you want to include them.", { :detected_multi_fields => multi_fields }) if multi_fields.any?

          if @target_field
            values_to_set = values.map do |row|
              mapped_data = column_specs.each_with_index.with_object({}) do |(column, index), mapped_data|
                # `unless value.nil?` is a part of `drop_null_columns` that if some of the columns' values are not `nil`, `nil` values appear,
                # we should continuously filter them out to achieve full `drop_null_columns` on each individual row (ideal `LIMIT 1` result)
                # we also exclude sub-elements of the base field
                if row[index] && sub_element_mark_map[column] == false
                  value_to_set = ESQL_PARSERS_BY_TYPE[column.type].call(row[index])
                  mapped_data[column.name] = value_to_set
                end
              end
              generate_nested_structure(mapped_data) unless mapped_data.empty?
            end
            event.set("[#{@target_field}]", values_to_set)
          else
            column_specs.zip(values.first).each do |(column, value) |
              if value && sub_element_mark_map[column] == false
                value_to_set = ESQL_PARSERS_BY_TYPE[column.type].call(value)
                event.set(column.field_reference, value_to_set)
              end
            end
          end
        end

        def inform_warning(response)
          return unless (warning = response&.headers&.dig('warning'))
          @logger.warn("ES|QL executor received warning", { message: warning })
        end

        # Transforms dotted keys to nested JSON shape
        # @param dot_keyed_hash [Hash] whose keys are dotted (example 'a.b.c.d': 'val')
        # @return [Hash] whose keys are nested with value mapped ({'a':{'b':{'c':{'d':'val'}}}})
        def generate_nested_structure(dot_keyed_hash)
          dot_keyed_hash.each_with_object({}) do |(key, value), result|
            key_parts = key.to_s.split('.')
            *path, leaf = key_parts
            leaf_scope = path.inject(result) { |scope, part| scope[part] ||= {} }
            leaf_scope[leaf] = value
          end
        end

        # Determines whether each column in a collection is a nested sub-element (e.g "user.age")
        # of another column in the same collection (e.g "user").
        #
        # @param columns [Array<ColumnSpec>] An array of objects with a `name` attribute representing field paths.
        # @return [Hash<ColumnSpec, Boolean>] A hash mapping each column to `true` if it is a sub-element of another field, `false` otherwise.
        # Time complexity: (O(NlogN+N*K)) where K is the number of conflict depth
        #   without (`prefix_set`) memoization, it would be O(N^2)
        def mark_sub_elements(columns)
          # Sort columns by name length (ascending)
          sorted_columns = columns.sort_by { |c| c.name.length }
          prefix_set = Set.new # memoization set

          sorted_columns.each_with_object({}) do |column, memo|
            # Split the column name into parts (e.g., "user.profile.age" → ["user", "profile", "age"])
            parts = column.name.split('.')

            # Generate all possible parent prefixes (e.g., "user", "user.profile")
            # and check if any parent prefix exists in the set
            parent_prefixes = (0...parts.size - 1).map { |i| parts[0..i].join('.') }
            memo[column] = parent_prefixes.any? { |prefix| prefix_set.include?(prefix) }
            prefix_set.add(column.name)
          end
        end
      end

      # Class representing a column specification in the ESQL response['columns']
      # The class's main purpose is to provide a structure for the event key
      # columns is an array with `name` and `type` pair (example: `{"name"=>"@timestamp", "type"=>"date"}`)
      # @attr_reader :name [String] The name of the column
      # @attr_reader :type [String] The type of the column
      class ColumnSpec
        attr_reader :name, :type

        def initialize(spec)
          @name = isolate(spec.fetch('name'))
          @type = isolate(spec.fetch('type'))
        end

        def field_reference
          @_field_reference ||= '[' + name.gsub('.', '][') + ']'
        end

        private
        def isolate(value)
          value.frozen? ? value : value.clone.freeze
        end
      end
    end
  end
end
