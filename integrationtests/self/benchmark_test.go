package self_test

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

func BenchmarkHandshake(b *testing.B) {
	b.ReportAllocs()

	ln, err := quic.ListenAddr("localhost:0", tlsConfig, nil)
	require.NoError(b, err)
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
	require.NoError(b, err)
	defer conn.Close()
	tr := &quic.Transport{Conn: conn}
	defer tr.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := tr.Dial(context.Background(), ln.Addr(), tlsClientConfig, nil)
		require.NoError(b, err)
		serverConn := <-connChan
		serverConn.CloseWithError(0, "")
		c.CloseWithError(0, "")
	}
}

func BenchmarkStreamChurn(b *testing.B) {
	b.ReportAllocs()

	ln, err := quic.ListenAddr("localhost:0", tlsConfig, &quic.Config{MaxIncomingStreams: 1e10})
	require.NoError(b, err)
	defer ln.Close()

	conn, err := quic.DialAddr(context.Background(), fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port), tlsClientConfig, nil)
	require.NoError(b, err)
	defer conn.CloseWithError(0, "")

	serverConn, err := ln.Accept(context.Background())
	require.NoError(b, err)
	defer serverConn.CloseWithError(0, "")

	go func() {
		for {
			str, err := serverConn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			str.Close()
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		str, err := conn.OpenStreamSync(context.Background())
		require.NoError(b, err)
		require.NoError(b, str.Close())
	}
}
