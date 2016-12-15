package main

import (
	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/utils"
)

func main() {
	addr := "https://quic.clemente.io:6121"

	utils.SetLogLevel(utils.LogLevelDebug)

	client, err := quic.NewClient(addr, func(bool) {}, func() error { return nil })
	if err != nil {
		panic(err)
	}

	err = client.Listen()
	defer client.Close()
	if err != nil {
		panic(err)
	}
}
