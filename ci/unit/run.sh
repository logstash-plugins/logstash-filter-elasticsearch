#!/bin/bash
# run from project root
set -e

whoami
if [ "$ELASTIC_STACK_VERSION" ]; then
    echo "Testing against version: $ELASTIC_STACK_VERSION"
    if [ -f Gemfile.lock ]; then
        rm Gemfile.lock
    fi
    docker-compose -f ci/unit/docker-compose.yml down
    docker-compose -f ci/unit/docker-compose.yml up --build --exit-code-from logstash --force-recreate
else
    echo "Please set the ELASTIC_STACK_VERSION environment variable"
    echo "For example: export ELASTIC_STACK_VERSION=6.2.4"
    exit 1
fi

