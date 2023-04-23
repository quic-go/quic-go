#!/bin/bash

set -e

dist="$1"
goos=$(echo "$dist" | cut -d "/" -f1)
goarch=$(echo "$dist" | cut -d "/" -f2)

# cross-compiling for android is a pain...
if [[ "$goos" == "android" ]]; then exit; fi
# iOS builds require Cgo, see https://github.com/golang/go/issues/43343
# Cgo would then need a C cross compilation setup. Not worth the hassle.
if [[ "$goos" == "ios" ]]; then exit; fi

echo "$dist"
out="main-$goos-$goarch"
GOOS=$goos GOARCH=$goarch go build -o $out example/main.go
rm $out
