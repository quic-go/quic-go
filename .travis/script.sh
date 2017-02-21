#!/usr/bin/env bash

set -e

go get -t ./...
if [ ${TESTMODE} == "unit" ]; then
  ginkgo -r --cover --randomizeAllSpecs --randomizeSuites --trace --progress --skipPackage integrationtests --skipMeasurements
fi

if [ ${TESTMODE} == "integration" ]; then
  ginkgo --randomizeAllSpecs --randomizeSuites --trace --progress -focus "Benchmark"
  ginkgo -r --randomizeAllSpecs --randomizeSuites --trace --progress integrationtests
fi
