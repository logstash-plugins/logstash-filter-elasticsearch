Gem::Specification.new do |s|

  s.name            = 'logstash-filter-elasticsearch'
  s.version         = '0.1.0'
  s.licenses        = ['Apache License (2.0)']
  s.summary         = "Search elasticsearch for a previous log event and copy some fields from it into the current event"
  s.description     = "Search elasticsearch for a previous log event and copy some fields from it into the current event."
  s.authors         = ["Elasticsearch"]
  s.email           = 'richard.pijnenburg@elasticsearch.com'
  s.homepage        = "http://logstash.net/"
  s.require_paths = ["lib"]

  # Files
  s.files = `git ls-files`.split($\)

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash', '>= 1.4.0', '< 2.0.0'
  s.add_runtime_dependency 'elasticsearch'

end

