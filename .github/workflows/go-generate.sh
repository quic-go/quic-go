#!/usr/bin/env bash

set -e

# delete all go-generated files (that adhere to the comment convention)
git ls-files -z | grep --include \*.go -lrIZ "^// Code generated .* DO NOT EDIT\.$" | tr '\0' '\n' | xargs rm -f

# First regenerate sys_conn_buffers_write.go.
# If it doesn't exist, the following mockgen calls will fail.
go generate -run "sys_conn_buffers_write.go"
# now generate everything
go generate ./...

# Check if any files were changed
git diff --exit-code || (
    echo "Generated files are not up to date. Please run 'go generate ./...' and commit the changes."
    exit 1
)
