#!/usr/bin/env bash

set -e

go get -t ./...

ginkgo -r --cover --randomizeAllSpecs --randomizeSuites --trace --progress --skipPackage integrationtests --skipMeasurements

# send coverage reports to Codecov
cat quic-go.coverprofile > coverage.txt
cat */*.coverprofile >> coverage.txt
bash <(curl -s https://codecov.io/bash) -f coverage.txt


