#!/bin/bash

# Mockgen refuses to generate mocks for internal packages.
# This script copies the internal directory and renames it to internalpackage.
# That way, mockgen can generate the mock.
# Afterwards, it corrects the import paths (replaces internalpackage back to internal).

TEMP_DIR=$(mktemp -d)
mkdir -p $TEMP_DIR/src/github.com/lucas-clemente/quic-go/internalpackage

cp -r $GOPATH/src/github.com/lucas-clemente/quic-go/internal/* $TEMP_DIR/src/github.com/lucas-clemente/quic-go/internalpackage
find $TEMP_DIR -type f -name "*.go" -exec sed -i '' 's/internal/internalpackage/g' {} \;

export GOPATH="$TEMP_DIR:$GOPATH"
PACKAGE_PATH=${3/internal/internalpackage}


mockgen -package $1 -self_package $1 -destination $2 $PACKAGE_PATH $4
sed -i '' 's/internalpackage/internal/g' $2

rm -r "$TEMP_DIR"
