package self_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

func BenchmarkHandshake(b *testing.B) {
	b.ReportAllocs()

	ln, err := quic.Listen(newUDPConnLocalhost(b), tlsConfig, nil)
	require.NoError(b, err)
	defer ln.Close()

	connChan := make(chan *quic.Conn, 1)
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			connChan <- conn
		}
	}()

	tr := &quic.Transport{Conn: newUDPConnLocalhost(b)}
	defer tr.Close()

	for b.Loop() {
		c, err := tr.Dial(context.Background(), ln.Addr(), tlsClientConfig, nil)
		if err != nil {
			b.Fatalf("error dialing: %v", err)
		}
		serverConn := <-connChan
		serverConn.CloseWithError(0, "")
		c.CloseWithError(0, "")
	}
}

func BenchmarkStreamChurn(b *testing.B) {
	b.ReportAllocs()

	ln, err := quic.Listen(newUDPConnLocalhost(b), tlsConfig, &quic.Config{MaxIncomingStreams: 1e10})
	require.NoError(b, err)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUDPConnLocalhost(b), ln.Addr(), tlsClientConfig, nil)
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

	for b.Loop() {
		str, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			b.Fatalf("error opening stream: %v", err)
		}
		if err := str.Close(); err != nil {
			b.Fatalf("error closing stream: %v", err)
		}
	}
}

func BenchmarkTransfer(b *testing.B) {
	b.Run(fmt.Sprintf("%d kb", len(PRData)/1024), func(b *testing.B) { benchmarkTransfer(b, PRData) })
	b.Run(fmt.Sprintf("%d kb", len(PRDataLong)/1024), func(b *testing.B) { benchmarkTransfer(b, PRDataLong) })
}

func benchmarkTransfer(b *testing.B, data []byte) {
	b.ReportAllocs()

	ln, err := quic.Listen(newUDPConnLocalhost(b), tlsConfig, nil)
	require.NoError(b, err)
	defer ln.Close()

	connChan := make(chan *quic.Conn, 1)
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			connChan <- conn
			str, err := conn.OpenUniStream()
			if err != nil {
				b.Logf("error opening stream: %v", err)
				return
			}
			if _, err := str.Write(data); err != nil {
				b.Logf("error writing data: %v", err)
				return
			}
			if err := str.Close(); err != nil {
				b.Logf("error closing stream: %v", err)
				return
			}
		}
	}()

	tr := &quic.Transport{Conn: newUDPConnLocalhost(b)}
	defer tr.Close()

	buf := make([]byte, len(data))

	for b.Loop() {
		c, err := tr.Dial(context.Background(), ln.Addr(), tlsClientConfig, nil)
		if err != nil {
			b.Fatalf("error dialing: %v", err)
		}

		str, err := c.AcceptUniStream(context.Background())
		if err != nil {
			b.Fatalf("error accepting stream: %v", err)
		}
		if _, err := io.ReadFull(str, buf); err != nil {
			b.Fatalf("error reading data: %v", err)
		}
		if _, err := str.Read([]byte{0}); err != io.EOF {
			b.Fatalf("error reading EOF: %v", err)
		}
		if !bytes.Equal(buf, data) {
			b.Fatalf("data mismatch: got %x, expected %x", buf, data)
		}

		serverConn := <-connChan
		serverConn.CloseWithError(0, "")
		c.CloseWithError(0, "")
	}
}
