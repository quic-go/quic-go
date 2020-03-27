package main

import (
	"context"
	"crypto/tls"
	"github.com/lucas-clemente/quic-go"
	"log"
	"sync/atomic"
	"time"
)

func clientMain() {
	// establish connection (session)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{tlsProto},
	}
	session, err := quic.DialAddr(addr, tlsConf, nil)
	if err != nil {
		log.Fatalln(err)
	}
	defer session.CloseWithError(0, "OK")
	// accept stream
	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		log.Fatalln(err)
	}
	defer stream.Close()
	log.Println("Stream accepted")
	// set up counter & channel
	var byteCounter uint64
	errChan := make(chan error)
	// receive data
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				atomic.AddUint64(&byteCounter, uint64(n))
			}
			if err != nil {
				errChan <- err
				break
			}
		}
	}()
	// speed display
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-errChan:
			log.Fatalln("Stream closed:", err)
		case <-ticker.C:
			c := atomic.LoadUint64(&byteCounter)
			atomic.StoreUint64(&byteCounter, 0)
			log.Printf("%.2f MB/s\n", float64(c)/1048576)
		}
	}
}
