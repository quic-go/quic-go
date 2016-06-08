#!/usr/bin/env bash

set -e

go get -t ./...
if [ ${TESTMODE} == "unit" ]; then
  ginkgo -r --cover --randomizeAllSpecs --randomizeSuites --trace --progress --skipPackage integrationtests
fi

if [ ${TESTMODE} == "integration" ]; then
  ginkgo -r --randomizeAllSpecs --randomizeSuites --trace --progress integrationtests
fi
