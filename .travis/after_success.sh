#!/usr/bin/env bash

set -ex

if [ ${TESTMODE} == "unit" ]; then
  cat `find . -name "*.coverprofile"` > coverage.txt
  bash <(curl -s https://codecov.io/bash) -f coverage.txt
fi
