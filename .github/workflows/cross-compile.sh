#!/bin/bash

set -e

for dist in $(go tool dist list); do
	goos=$(echo $dist | cut -d "/" -f1)
	goarch=$(echo $dist | cut -d "/" -f2)
	# cross-compiling for android is a pain...
	if [[ "$goos" == "android" ]]; then continue; fi
  # iOS builds require Cgo, see https://github.com/golang/go/issues/43343
  # Cgo would then need a C cross compilation setup. Not worth the hassle.
	if [[ "$goos" == "ios" ]]; then continue; fi

	echo "$dist"
	GOOS=$goos GOARCH=$goarch go build -o main example/main.go
	rm main
done
