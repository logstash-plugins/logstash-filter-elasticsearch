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
