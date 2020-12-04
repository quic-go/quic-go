#!/bin/bash

set -e

GOVERSION=$(go version | cut -d " " -f 3 | cut -b 3-6)

for dist in $(go tool dist list); do
	goos=$(echo $dist | cut -d "/" -f1)
	goarch=$(echo $dist | cut -d "/" -f2)
	if [[ "$goos" == "android" ]]; then continue; fi 		# cross-compiling for android is a pain...
	if [[ "$goos" == "darwin" && $goarch == "arm64" ]]; then continue; fi # ... darwin/arm64 neither
	if [[ $GOVERSION == "1.14" && $goos == "darwin" && $goarch == "arm" ]]; then continue; fi # Go 1.14 lacks syscall.IPV6_RECVTCLASS

	echo "$dist"
	GOOS=$goos GOARCH=$goarch go build -o main example/main.go
	rm main
done
