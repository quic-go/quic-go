#!/bin/bash
# Helper script to run tests with the required GOEXPERIMENT flag for Go 1.24
# See .github/workflows/unit.yml for the CI configuration

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')

if [[ $GO_VERSION == 1.24.* ]]; then
    echo "Running tests with GOEXPERIMENT=synctest for Go 1.24"
    GOEXPERIMENT=synctest go test "$@" ./...
elif [[ $GO_VERSION == 1.25.* ]]; then
    echo "Running tests for Go 1.25 (synctest is stable)"
    go test "$@" ./...
else
    echo "Warning: Untested Go version $GO_VERSION"
    go test "$@" ./...
fi
