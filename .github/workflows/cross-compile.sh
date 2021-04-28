#!/bin/bash

set -e

GOVERSION=$(go version | cut -d " " -f 3 | cut -b 3-6)

for dist in $(go tool dist list); do
	goos=$(echo $dist | cut -d "/" -f1)
	goarch=$(echo $dist | cut -d "/" -f2)
	# cross-compiling for android is a pain...
	if [[ "$goos" == "android" ]]; then continue; fi
	# Go 1.14 lacks syscall.IPV6_RECVTCLASS
	if [[ $GOVERSION == "1.14" && $goos == "darwin" && $goarch == "arm" ]]; then continue; fi
	# darwin/arm64 requires Cgo for Go < 1.16
	if [[ $GOVERSION != "1.16" && "$goos" == "darwin" && $goarch == "arm64" ]]; then continue; fi
  # iOS builds require Cgo, see https://github.com/golang/go/issues/43343
  # Cgo would then need a C cross compilation setup. Not worth the hassle.
	if [[ "$goos" == "ios" ]]; then continue; fi

	echo "$dist"
	GOOS=$goos GOARCH=$goarch go build -o main example/main.go
	rm main
done
