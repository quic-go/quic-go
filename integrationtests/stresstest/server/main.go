package main

import (
	"io"
	"log"
	"os"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/testdata"
)

func main() {
	f, err := os.Create("./log_server.txt")
	defer f.Close()
	if err != nil {
		panic(err)
	}
	log.SetOutput(f)

	conf := &quic.Config{TLSConfig: testdata.GetTLSConfig()}
	server, err := quic.ListenAddr("localhost:12345", conf)
	if err != nil {
		panic(err)
	}

	for {
		sess, err := server.Accept()
		if err != nil {
			panic(err)
		}

		go func() {
			for {
				str, err := sess.AcceptStream()
				if err != nil { // the session was closed
					return
				}
				go func() {
					io.Copy(str, str)
					str.Close()
				}()
			}
		}()
	}
}
