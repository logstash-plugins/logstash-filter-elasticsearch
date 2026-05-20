## 4.3.1
  - Added support for encoded and non encoded api-key formats on plugin configuration [#203](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/203)

## 4.3.0
  - ES|QL support [#194](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/194)

## 4.2.0
  - Add `target` configuration option to store the result into it [#196](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/196)

## 4.1.1
  - Add elastic-transport client support used in elasticsearch-ruby 8.x [#191](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/191)

## 4.1.0
 - Added support for custom headers [#188](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/188)

## 4.0.0
  - SSL settings that were marked deprecated in version `3.15.0` are now marked obsolete, and will prevent the plugin from starting.
  - These settings are:
    - `ca_file`, which should be replaced by `ssl_certificate_authorities`
    - `keystore`, which should be replaced by `ssl_keystore_path`
    - `keystore_password`, which should be replaced by `ssl_keystore_password`
    - `keystore_type`, which should be replaced by `ssl_keystore_password`
    -  `ssl`, which should be replaced by `ssl_enabled`
    - [#183](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/183)

## 3.16.2
  - Add `x-elastic-product-origin` header to Elasticsearch requests [#185](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/185)

## 3.16.1
  - Version bump to pick up doc fix in [#172](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/172)

## 3.16.0
  - Added request header `Elastic-Api-Version` for serverless [#174](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/174)

## 3.15.3
  - Fixes a memory leak that occurs when a pipeline containing this filter terminates, which could become significant if the pipeline is cycled repeatedly [#173](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/173)

## 3.15.2
  - Added checking for `query` and `query_template`. [#171](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/171)
  
## 3.15.1
  - Fixes a regression introduced in 3.15.0 which could prevent a connection from being established to Elasticsearch in some SSL configurations

## 3.15.0
  - Added SSL settings for: [#168](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/168)
    - `ssl_enabled`: Enable/disable the SSL settings. If not provided, the value is inferred from the hosts scheme
    - `ssl_certificate`: OpenSSL-style X.509 certificate file to authenticate the client
    - `ssl_key`: OpenSSL-style RSA private key that corresponds to the `ssl_certificate`
    - `ssl_truststore_path`: The JKS truststore to validate the server's certificate
    - `ssl_truststore_type`: The format of the truststore file
    - `ssl_truststore_password`: The truststore password
    - `ssl_keystore_path`: The keystore used to present a certificate to the server
    - `ssl_keystore_type`: The format of the keystore file
    - `ssl_keystore_password`: The keystore password
    - `ssl_cipher_suites`: The list of cipher suites to use
    - `ssl_supported_protocols`: Supported protocols with versions
    - `ssl_verification_mode`: Defines how to verify the certificates presented by another party in the TLS connection
  - Reviewed and deprecated SSL settings to comply with Logstash's naming convention
    - Deprecated `ssl` in favor of `ssl_enabled`
    - Deprecated `ca_file` in favor of `ssl_certificate_authorities`
    - Deprecated `keystore` in favor of `ssl_keystore_path`
    - Deprecated `keystore_password` in favor of `ssl_keystore_password`

## 3.14.0
  - Added support for configurable retries with new `retry_on_failure` and `retry_on_status` options [#160](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/160)

## 3.13.0
  - Added support for this plugin identifying itself to Elasticsearch with an SSL/TLS client certificate using a new `keystore` option [#162](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/162)

## 3.12.0
  - Added support for `ca_trusted_fingerprint` when run on Logstash 8.3+ [#158](https://github.com/logstash-plugins/logstash-filter-elasticsearch/pull/158)

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
