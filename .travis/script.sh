#!/usr/bin/env bash

set -ex

# run benchmark tests
ginkgo -randomizeAllSpecs -randomizeSuites -trace benchmark -- -size=10
# run benchmark tests with the Go race detector
# The Go race detector only works on amd64.
if [ "${TRAVIS_GOARCH}" != '386' ]; then
	ginkgo -race -randomizeAllSpecs -randomizeSuites -trace benchmark -- -size=5
fi
# run integration tests
ginkgo -r -v -randomizeAllSpecs -randomizeSuites -trace integrationtests
