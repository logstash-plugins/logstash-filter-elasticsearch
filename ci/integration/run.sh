#!/bin/bash
# run from project root
set -e

if [ "$ELASTIC_STACK_VERSION" ]; then
    echo "Testing against version: $ELASTIC_STACK_VERSION"
    find . -name *.gemspec | xargs gem build
    cp *.gem ci/integration/this.gem
    source ci/integration/config.sh
    docker-compose -f ci/integration/docker-compose.yml down
    docker-compose -f ci/integration/docker-compose.yml up --exit-code-from logstash --force-recreate &
    # TODO kick off the actual tests to busy wait for startup and upon exit from that docker-compose down
    #docker-compose -f ci/unit/docker-compose.yml down
else
    echo "Please set the ELASTIC_STACK_VERSION environment variable"
    echo "For example: export ELASTIC_STACK_VERSION=6.2.4"
    exit 1
fi




