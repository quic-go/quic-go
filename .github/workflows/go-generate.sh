#!/usr/bin/env bash

set -e

DIR=$(pwd)
TMP=$(mktemp -d)
cd "$TMP"
cp -r "$DIR" orig
cp -r "$DIR" generated

cd generated
# delete all go-generated files generated (that adhere to the comment convention)
grep --include \*.go -lrIZ "^// Code generated .* DO NOT EDIT\.$" . | xargs --null rm

# First regenerate sys_conn_buffers_write.go.
# If it doesn't exist, the following mockgen calls will fail.
go generate -run "sys_conn_buffers_write.go"
# now generate everything
go generate ./...
cd ..

# don't compare fuzzing corpora
diff --exclude=corpus --exclude=.git -ruN orig generated
