# A QUIC implementation in native Go

[![Build Status](https://travis-ci.org/lucas-clemente/quic-go.svg?branch=master)](https://travis-ci.org/lucas-clemente/quic-go)
[![Godoc Reference](https://godoc.org/github.com/lucas-clemente/quic-go?status.svg)](https://godoc.org/github.com/lucas-clemente/quic-go)

This is very much an incomplete, buggy, unperformant and insecure work in progress :)

Installing deps:

    go get -t

Running the example server:

    go run example/main.go

Using the `quic_client` from chromium:

    quic_client --host=127.0.0.1 --port=6121 --v=1 https://quic.clemente.io

Using Chrome:

    /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --user-data-dir=/tmp/chrome --no-proxy-server --enable-quic --origin-to-force-quic-on=quic.clemente.io:443 --host-resolver-rules='MAP quic.clemente.io:443 127.0.0.1:6121' https://quic.clemente.io
