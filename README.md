# A QUIC server implementation in pure Go

<img src="docs/quic.png" width=303 height=124>

[![Build Status](https://travis-ci.org/lucas-clemente/quic-go.svg?branch=master)](https://travis-ci.org/lucas-clemente/quic-go)
[![Godoc Reference](https://godoc.org/github.com/lucas-clemente/quic-go?status.svg)](https://godoc.org/github.com/lucas-clemente/quic-go)

This is very much an incomplete, buggy, unperformant and insecure work in progress :)

## Features

Done:

- Basic protocol with support for QUIC version 30, 31 and 32
- HTTP/2 support
- Crypto (RSA for signing, curve25519 for KEX, chacha20-poly1305 as cipher)
- Loss detection and retransmission (currently fast retransmission & RTO)
- Flow Control
- Congestion control using cubic

Major TODOs:

- Security, especially DOS protections
- Performance
- Better packet loss detection
- Support for QUIC versions 33 & 34
- Connection migration
- QUIC client
- Public API design
- Integration into caddy (mostly to figure out the right server API)

## Guides

Installing deps:

    go get -t

Running tests:

    go test ./...

Running the example server:

    go run example/main.go -www /var/www/

Using the `quic_client` from chromium:

    quic_client --quic-version=32 --host=127.0.0.1 --port=6121 --v=1 https://quic.clemente.io

Using Chrome:

    /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --user-data-dir=/tmp/chrome --no-proxy-server --enable-quic --origin-to-force-quic-on=quic.clemente.io:443 --host-resolver-rules='MAP quic.clemente.io:443 127.0.0.1:6121' https://quic.clemente.io

## Usage

See the [example server](example/main.go) or our [fork](https://github.com/lucas-clemente/caddy) of caddy. Starting a QUIC server is very similar to the standard lib http in go:

```go
http.Handle("/", http.FileServer(http.Dir(wwwDir)))

server, _ := h2quic.NewServer(tlsConfig)

server.ListenAndServe("localhost:4242", nil /* use http.DefaultServeMux */)
```
