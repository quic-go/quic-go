package self_test

import (
	"context"
	"fmt"
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
	ln, err := quic.ListenAddrEarly("localhost:0", getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
		RemoteAddr:  fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
		DelayPacket: func(quicproxy.Direction, []byte) time.Duration { return rtt / 2 },
	})
	require.NoError(t, err)
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

	clientConn, err := quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", proxy.LocalPort()),
		getTLSClientConfig(),
		getQuicConfig(nil),
	)
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
