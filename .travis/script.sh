#!/usr/bin/env bash

set -ex

if [ "${TESTMODE}" == "unit" ]; then
  ginkgo -r -v -cover -randomizeAllSpecs -randomizeSuites -trace -skipPackage integrationtests,benchmark
  # run unit tests with the Go race detector
  # The Go race detector only works on amd64.
  if [ "${TRAVIS_GOARCH}" == 'amd64' ]; then
    ginkgo -race -r -v -randomizeAllSpecs -randomizeSuites -trace -skipPackage integrationtests,benchmark
  fi
fi

if [ "${TESTMODE}" == "integration" ]; then
  # run benchmark tests
  ginkgo -randomizeAllSpecs -randomizeSuites -trace benchmark -- -size=10
  # run benchmark tests with the Go race detector
  # The Go race detector only works on amd64.
  if [ "${TRAVIS_GOARCH}" == 'amd64' ]; then
    ginkgo -race -randomizeAllSpecs -randomizeSuites -trace benchmark -- -size=5
  fi
  # run integration tests
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -trace integrationtests
fi
