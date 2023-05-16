Gem::Specification.new do |s|

  s.name            = 'logstash-filter-opensearch-manticore'
  s.version         = '0.1.1'
  s.licenses        = ['Apache License (2.0)']
  s.summary         = "Copies fields from previous log.json events in OpenSearch to current events "
  s.description     = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors         = ["Anton Klyba"]
  s.email           = 'anarhyst266@gmail.com'
  s.homepage        = "https://github.com/Anarhyst266/logstash-filter-opensearch-manticore"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir["lib/**/*","spec/**/*","*.gemspec","*.md","CONTRIBUTORS","Gemfile","LICENSE","NOTICE.TXT", "vendor/jar-dependencies/**/*.jar", "vendor/jar-dependencies/**/*.rb", "VERSION", "docs/**/*"]

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.60", "<= 2.99"
  s.add_runtime_dependency 'opensearch-ruby'
  s.add_runtime_dependency 'manticore', "~> 0.6"

  s.add_development_dependency 'logstash-devutils'
end

