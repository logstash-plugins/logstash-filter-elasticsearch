#!/bin/bash
set -ex

export PATH=$BUILD_DIR/gradle/bin:$PATH

# CentOS 7 using curl defaults does not enable TLSv1.3
CURL_OPTS="-k --tlsv1.2 --tls-max 1.3"

wait_for_es() {
  echo "Waiting for elasticsearch to respond..."
  es_url="http://elasticsearch:9200"
  if [[ "$SECURE_INTEGRATION" == "true" ]]; then
    es_url="https://elasticsearch:9200"
  fi
  count=120
  while ! curl $CURL_OPTS -u elastic:$ELASTIC_PASSWORD --silent $es_url && [[ $count -ne 0 ]]; do
    count=$(( $count - 1 ))
    [[ $count -eq 0 ]] && return 1
    sleep 1
  done
  echo "Elasticsearch is Up !"

  return 0
}

if [[ "$INTEGRATION" != "true" ]]; then
  bundle exec rspec --format=documentation spec/filters --tag ~integration
else
  # SECURE_INTEGRATION is handled inside the specs
  extra_tag_args="--tag integration"

  wait_for_es
  bundle exec rspec --format=documentation $extra_tag_args --tag update_tests:painless --tag es_version:$ELASTIC_STACK_VERSION spec/filters/integration
fi
