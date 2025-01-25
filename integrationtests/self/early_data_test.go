package self_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	"github.com/stretchr/testify/require"
)

func TestEarlyData(t *testing.T) {
	const rtt = 80 * time.Millisecond
	ln, err := quic.ListenEarly(newUPDConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	proxy := &quicproxy.Proxy{
		Conn:        newUPDConnLocalhost(t),
		ServerAddr:  ln.Addr().(*net.UDPAddr),
		DelayPacket: func(quicproxy.Direction, []byte) time.Duration { return rtt / 2 },
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	connChan := make(chan quic.EarlyConnection)
	errChan := make(chan error)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			errChan <- err
			return
		}
		connChan <- conn
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientConn, err := quic.Dial(ctx, newUPDConnLocalhost(t), proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)

	var serverConn quic.EarlyConnection
	select {
	case serverConn = <-connChan:
	case err := <-errChan:
		t.Fatalf("error accepting connection: %s", err)
	}
	str, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("early data"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	// the write should have completed before the handshake
	select {
	case <-serverConn.HandshakeComplete():
		t.Fatal("handshake shouldn't be completed yet")
	default:
	}

	clientStr, err := clientConn.AcceptUniStream(context.Background())
	require.NoError(t, err)
	data, err := io.ReadAll(clientStr)
	require.NoError(t, err)
	require.Equal(t, []byte("early data"), data)

	clientConn.CloseWithError(0, "")
	<-serverConn.Context().Done()
}
