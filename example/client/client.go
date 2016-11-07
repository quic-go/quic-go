package main

import (
	"net"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/utils"
)

func main() {
	addr := "quic.clemente.io:6121"

	utils.SetLogLevel(utils.LogLevelDebug)

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}

	client, err := quic.NewClient(udpAddr)
	if err != nil {
		panic(err)
	}

	client.Listen()
}
