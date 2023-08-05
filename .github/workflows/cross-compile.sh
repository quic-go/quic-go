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

# Write all log output to a temporary file instead of to stdout.
# That allows running this script in parallel, while preserving the correct order of the output.
log_file=$(mktemp)

error_handler() {
  cat "$log_file" >&2
  rm "$log_file"
  exit 1
}

trap 'error_handler' ERR

echo "$dist" >> "$log_file"
out="main-$goos-$goarch"
GOOS=$goos GOARCH=$goarch go build -o $out example/main.go >> "$log_file" 2>&1
rm $out

cat "$log_file"
rm "$log_file"
