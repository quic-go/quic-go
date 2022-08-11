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
# now generate everything
go generate ./...
cd ..

# don't compare fuzzing corpora
diff --exclude=corpus --exclude=.git -ruN orig generated
