#!/bin/bash

# Mockgen refuses to generate mocks for internal packages.
# This script copies the internal directory and renames it to internalpackage.
# That way, mockgen can generate the mock.
# Afterwards, it corrects the import paths (replaces internalpackage back to internal).

TEMP_DIR=$(mktemp -d)
mkdir -p $TEMP_DIR/src/github.com/lucas-clemente/quic-go/

cp -r $GOPATH/src/github.com/lucas-clemente/quic-go/ $TEMP_DIR/src/github.com/lucas-clemente/quic-go/
echo "type StreamI = streamI" >> $TEMP_DIR/src/github.com/lucas-clemente/quic-go/stream.go

export GOPATH="$TEMP_DIR:$GOPATH"

mockgen -package $1 -self_package $1 -destination $2 $3 $4

rm -r "$TEMP_DIR"
