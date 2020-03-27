package main

import (
	"flag"
)

const tlsProto = "quic-custom-cc-example"
const dataSize = 104857600

var isServer bool
var addr string
var sendSpeed uint64 // bytes per second
var disableCustomCC bool

func init() {
	flag.BoolVar(&isServer, "server", false, "server mode")
	flag.StringVar(&addr, "addr", "", "address")
	flag.Uint64Var(&sendSpeed, "speed", 1048576, "bytes per second send speed for server")
	flag.BoolVar(&disableCustomCC, "disable-custom-cc", false, "disable custom cc")
	flag.Parse()
}

func main() {
	if !isServer {
		clientMain()
	} else {
		serverMain()
	}
}
