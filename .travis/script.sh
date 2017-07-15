#!/usr/bin/env bash

set -e

go get -t ./...
if [ ${TESTMODE} == "unit" ]; then
  ginkgo -r --cover --randomizeAllSpecs --randomizeSuites --trace --progress --skipPackage integrationtests --skipMeasurements
fi

if [ ${TESTMODE} == "integration" ]; then
  # run benchmark tests
  ginkgo --randomizeAllSpecs --randomizeSuites --trace --progress -focus "Benchmark"
  # run benchmark tests with the Go race detector
  # The Go race detector only works on amd64.
  if [ ${TRAVIS_GOARCH} == 'amd64' ]; then
    ginkgo --race --randomizeAllSpecs --randomizeSuites --trace --progress -focus "Benchmark"
  fi
  # run integration tests
  ginkgo -v -r --randomizeAllSpecs --randomizeSuites --trace --progress integrationtests
fi
