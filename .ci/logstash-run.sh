#!/bin/bash
set -ex

export PATH=$BUILD_DIR/gradle/bin:$PATH

wait_for_es() {
  echo "Waiting for elasticsearch to respond..."
  es_url="http://elasticsearch:9200"
  count=120
  while ! curl -u elastic:$ELASTIC_PASSWORD --silent $es_url && [[ $count -ne 0 ]]; do
    count=$(( $count - 1 ))
    [[ $count -eq 0 ]] && return 1
    sleep 1
  done
  echo "Elasticsearch is Up !"

  return 0
}

if [[ "$INTEGRATION" != "true" ]]; then
  jruby -rbundler/setup -S rspec -fd -t ~integration spec/filters
else
  extra_tag_args="-t integration"
  wait_for_es
  jruby -rbundler/setup -S rspec -fd $extra_tag_args -t es_version:$ELASTIC_STACK_VERSION spec/filters/integration
fi
