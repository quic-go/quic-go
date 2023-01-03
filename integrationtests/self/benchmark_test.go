package self_test

import (
	"context"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
)

func BenchmarkHandshake(b *testing.B) {
	b.ReportAllocs()

	ln, err := quic.ListenAddr("localhost:0", tlsConfig, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	connChan := make(chan quic.Connection, 1)
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			connChan <- conn
		}
	}()

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := quic.Dial(conn, ln.Addr(), "localhost", tlsClientConfig, nil)
		if err != nil {
			b.Fatal(err)
		}
		<-connChan
		c.CloseWithError(0, "")
	}
}
