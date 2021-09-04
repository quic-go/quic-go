package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"

	quic "github.com/lucas-clemente/quic-go"
)

const Caddr = "localhost:4242"

var qconf quic.Config

func main() {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"wq-vvv-01"},
	}
	qconf.KeepAlive = true
	session, err := quic.DialAddr(Caddr, tlsConf, &qconf)
	if err != nil {
		return
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		fmt.Println("in sream", err)
		return
	}
	// In case, want to read in parallel with write
	// go func() {
	// 	for {
	// 		fmt.Println("Client: Reading")
	// 		buf := make([]byte, 1500)
	// 		_, err = stream.Read(buf)
	// 		if err != nil {
	// 			log.Println("Stream Read error: ", err)
	// 			return
	// 		}
	// 		fmt.Println("2Read: ", string(buf))
	// 	}
	// }()
	fmt.Println("Client sending Hello")
	_, err = stream.Write([]byte("Hello from Client"))
	if err != nil {
		log.Println("Stream write error: ", err)
	}

	buf := make([]byte, 1500)
	_, err = stream.Read(buf)
	if err != nil {
		log.Println("Stream Read error: ", err)
		return
	}
	fmt.Println("client Received: ", string(buf))

	stream.Close()
	session.CloseWithError(10, "Done")

}
