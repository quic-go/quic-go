#!/usr/bin/env bash

set -e

go get -t ./...

ginkgo --randomizeAllSpecs --randomizeSuites --trace --progress -focus "Benchmark"
ginkgo -r --randomizeAllSpecs --randomizeSuites --trace --progress integrationtests
