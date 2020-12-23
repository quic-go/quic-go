#!/bin/bash

set -e

GOVERSION=$(go version | cut -d " " -f 3 | cut -b 3-6)

for dist in $(go tool dist list); do
	goos=$(echo $dist | cut -d "/" -f1)
	goarch=$(echo $dist | cut -d "/" -f2)
	if [[ "$goos" == "android" ]]; then continue; fi 		# cross-compiling for android is a pain...
	if [[ "$goos" == "darwin" && $goarch == "arm64" ]]; then continue; fi # ... darwin/arm64 neither
	if [[ $GOVERSION == "1.14" && $goos == "darwin" && $goarch == "arm" ]]; then continue; fi # Go 1.14 lacks syscall.IPV6_RECVTCLASS

	cgo=0
	if [[ "$goos" == "ios" ]]; then cgo=1; fi # iOS builds require CGO, see https://github.com/golang/go/issues/43343

	echo "$dist"
	GOOS=$goos GOARCH=$goarch CGO_ENABLED=$cgo go build -o main example/main.go
	rm main
done
