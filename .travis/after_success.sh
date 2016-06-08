#!/usr/bin/env bash

set -e

if [ ${TESTMODE} == "unit" ]; then
  cat quic-go.coverprofile > coverage.txt
  cat */*.coverprofile >> coverage.txt
  bash <(curl -s https://codecov.io/bash) -f coverage.txt
fi
