#!/bin/bash

# Mockgen refuses to generate mocks private types.
# This script copies the quic package to a temporary directory, and adds an public alias for the private type.
# It then creates a mock for this public (alias) type.

TEMP_DIR=$(mktemp -d)
mkdir -p $TEMP_DIR/src/github.com/lucas-clemente/quic-go/

# copy all .go files to a temporary directory
rsync -r --include='*.go' --include '*/' --exclude '*' $GOPATH/src/github.com/lucas-clemente/quic-go/ $TEMP_DIR/src/github.com/lucas-clemente/quic-go/
echo "type $5 = $4" >> $TEMP_DIR/src/github.com/lucas-clemente/quic-go/interface.go

export GOPATH="$TEMP_DIR:$GOPATH"

mockgen -package $1 -self_package $1 -destination $2 $3 $5

rm -r "$TEMP_DIR"
