#!/usr/bin/env bash

set -ex

go get -t ./...
if [ ${TESTMODE} == "lint" ]; then 
  go get github.com/alecthomas/gometalinter
  gometalinter --install
  gometalinter --deadline=300s --tests ./...
fi

if [ ${TESTMODE} == "unit" ]; then
  ginkgo -r -v -cover -randomizeAllSpecs -randomizeSuites -trace -skipPackage integrationtests,benchmark
fi

if [ ${TESTMODE} == "integration" ]; then
  # run benchmark tests
  ginkgo -randomizeAllSpecs -randomizeSuites -trace benchmark -- -samples=1
  # run benchmark tests with the Go race detector
  # The Go race detector only works on amd64.
  if [ ${TRAVIS_GOARCH} == 'amd64' ]; then
    ginkgo -race -randomizeAllSpecs -randomizeSuites -trace benchmark -- -samples=1 -size=10
  fi
  # run integration tests
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -trace integrationtests
fi
