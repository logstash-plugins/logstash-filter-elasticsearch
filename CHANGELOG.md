## 3.11.1
  -  Fix: hosts => "es_host:port" regression [#156](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/156)

## 3.11.0
  - Feat: update Elasticsearch client to 7.14.0 [#150](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/150)

## 3.10.0
  - Feat: add user-agent header passed to the Elasticsearch HTTP connection [#152](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/152)

## 3.9.5
  - Fixed SSL handshake hang indefinitely with proxy setup [#151](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/151)

## 3.9.4
  - Fix: a regression (in LS 7.14.0) where due the elasticsearch client update (from 5.0.5 to 7.5.0) the `Authorization` 
    header isn't passed, this leads to the plugin not being able to leverage `user`/`password` credentials set by the user.
    [#148](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/148)
  - Fix: default setting for `hosts` not working (since 3.7.0) GH-147
  - Fix: mutating @hosts variable which leads to issues with multiple worker threads GH-129

## 3.9.3
  - [DOC] Update links to use shared attributes [#144](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/144)

## 3.9.2
  - [DOC] Fixed links to restructured Logstash-to-cloud docs [#142](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/142)

## 3.9.1
  - [DOC] Document the permissions required in secured clusters [#140](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/140)
  
## 3.9.0
  - Add support to define a proxy with the proxy config option [#134](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/134)

## 3.8.0
  - Added api_key support [#132](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/132)

## 3.7.2
  - [DOC] Removed outdated compatibility notice [#131](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/131)

## 3.7.1
  - Fix: solves an issue where non-ascii unicode values in a template were not handled correctly [#128](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/128)

## 3.7.0
  - Feat: support cloud_id / cloud_auth configuration [#122](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/122)

## 3.6.1
  - Loosen restrictions on Elasticsearch gem ([#120](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/120))

## 3.6.0
  - Add support for extracting hits total from Elasticsearch 7.x responses

## 3.5.0
  - Added connection check during register to avoid failures during processing
  - Changed Elasticsearch Client transport to use Manticore
  - Changed amount of logging details during connection failure

## 3.4.0
  - Adds `[@metadata][total_hits]` with total hits returned from the query ([#106](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/106))
  - Improves error logging to fully inspect caught exceptions ([#105](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/105))

## 3.3.1
  - Fix: The filter now only calls `filter_matched` on events that actually matched.
    This fixes issues where all events would have success-related actions happened
    when no match had actually happened (`add_tag`, `add_field`, `remove_tag`,
    `remove_field`)

## 3.3.0
  - Enhancement : if elasticsearch response contains any shard failure, then `tag_on_failure` tags are added to Logstash event
  - Enhancement : add support for nested fields
  - Enhancement : add 'docinfo_fields' option
  - Enhancement : add 'aggregation_fields' option

## 3.2.1
  - Update gemspec summary

## 3.2.0
  - `index` setting now supports field formatting, such as `index => "%{myindex}"` (Boris Gorbylev)

## 3.1.8
  - Fix a thread safety issue when using this filter with multiple workers on heavy load, we now create an elasticsearch client for every LogStash worker. #76

## 3.1.6
  - Fix some documentation issues

## 3.1.5
 - Docs: Fix broken link to Logstash docs.
 - Support ca_file setting when using https uri in hosts parameter

## 3.1.4
 - Docs: Bump patch level for doc build.

## 3.1.3
  - Change the queries loglevel from info to debug.

## 3.1.2
  - Docs: Add requirement to use version 3.1.1 or higher to support sending Content-Type headers.
  
## 3.1.1
  - Upgrade es-ruby client to support correct content-type

## 3.1.0
  - Support for full use of query DSL. Added query_template to use full DSL.

## 3.0.3
  - Fix couple of bugs related to incorrect variable names

## 3.0.2
  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 3.0.1
- Fix: wrong usage of search params, now if index is properly specified
  it's passed to search so it's performed not to all indices if this is not the explicit intention.
## 3.0.0
  - Breaking: Updated plugin to use new Java Event APIs
## 2.1.0
  - Improved the configuration options to be more easy to understand and
    match what the expectations are from the documentation.
  - Initial refactoring to include later one a common client for all the
    ES plugins.
  - Adding support for having an index in the query pattern.
  - Improved documentation.
  - Added intitial integration and unit tests.
## 2.0.4
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash
## 2.0.3
  - New dependency requirements for logstash-core for the 5.0 release
## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully, 
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0
## 0.1.6
- removed require statement for a file that is no longer present in logstash-core.
