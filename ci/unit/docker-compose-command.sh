#!/bin/bash

set -ex

export PATH=$PATH:$PWD/vendor/jruby/bin
gem install bundler
cd ../plugins/this
cp /usr/share/logstash/logstash-core/versions-gem-copy.yml /usr/share/logstash/logstash-core-plugin-api/versions-gem-copy.yml
bundle install
bundle exec rspec spec