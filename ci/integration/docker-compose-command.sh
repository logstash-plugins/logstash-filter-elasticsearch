#!/bin/bash

set -ex

bin/logstash-plugin install ./this.gem
bin/logstash $@


