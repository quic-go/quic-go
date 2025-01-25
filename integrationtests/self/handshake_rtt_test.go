package self_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	"github.com/stretchr/testify/require"
)

func handshakeWithRTT(t *testing.T, serverAddr net.Addr, tlsConf *tls.Config, quicConf *quic.Config, rtt time.Duration) quic.Connection {
	t.Helper()

	proxy := quicproxy.Proxy{
		Conn:        newUPDConnLocalhost(t),
		ServerAddr:  serverAddr.(*net.UDPAddr),
		DelayPacket: func(quicproxy.Direction, []byte) time.Duration { return rtt / 2 },
	}
	require.NoError(t, proxy.Start())
	t.Cleanup(func() { proxy.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*rtt)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		newUPDConnLocalhost(t),
		proxy.LocalAddr(),
		tlsConf,
		quicConf,
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	return conn
}

func TestHandshakeRTTWithoutRetry(t *testing.T) {
	ln, err := quic.Listen(newUPDConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	clientConfig := getQuicConfig(&quic.Config{
		GetConfigForClient: func(info *quic.ClientHelloInfo) (*quic.Config, error) {
			require.False(t, info.AddrVerified)
			return nil, nil
		},
	})

	const rtt = 400 * time.Millisecond
	start := time.Now()
	handshakeWithRTT(t, ln.Addr(), getTLSClientConfig(), clientConfig, rtt)
	rtts := time.Since(start).Seconds() / rtt.Seconds()
	require.GreaterOrEqual(t, rtts, float64(1))
	require.Less(t, rtts, float64(2))
}

func TestHandshakeRTTWithRetry(t *testing.T) {
	tr := &quic.Transport{
		Conn:                newUPDConnLocalhost(t),
		VerifySourceAddress: func(net.Addr) bool { return true },
	}
	addTracer(tr)
	defer tr.Close()
	ln, err := tr.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	clientConfig := getQuicConfig(&quic.Config{
		GetConfigForClient: func(info *quic.ClientHelloInfo) (*quic.Config, error) {
			require.True(t, info.AddrVerified)
			return nil, nil
		},
	})
	const rtt = 400 * time.Millisecond
	start := time.Now()
	handshakeWithRTT(t, ln.Addr(), getTLSClientConfig(), clientConfig, rtt)
	rtts := time.Since(start).Seconds() / rtt.Seconds()
	require.GreaterOrEqual(t, rtts, float64(2))
	require.Less(t, rtts, float64(3))
}

func TestHandshakeRTTWithHelloRetryRequest(t *testing.T) {
	tlsConf := getTLSConfig()
	tlsConf.CurvePreferences = []tls.CurveID{tls.CurveP384}

	ln, err := quic.Listen(newUPDConnLocalhost(t), tlsConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	const rtt = 400 * time.Millisecond
	start := time.Now()
	handshakeWithRTT(t, ln.Addr(), getTLSClientConfig(), getQuicConfig(nil), rtt)
	rtts := time.Since(start).Seconds() / rtt.Seconds()
	require.GreaterOrEqual(t, rtts, float64(2))
	require.Less(t, rtts, float64(3))
}

func TestHandshakeRTTReceiveMessage(t *testing.T) {
	sendAndReceive := func(t *testing.T, serverConn, clientConn quic.Connection) {
		t.Helper()
		serverStr, err := serverConn.OpenUniStream()
		require.NoError(t, err)
		_, err = serverStr.Write([]byte("foobar"))
		require.NoError(t, err)
		require.NoError(t, serverStr.Close())

		str, err := clientConn.AcceptUniStream(context.Background())
		require.NoError(t, err)
		data, err := io.ReadAll(str)
		require.NoError(t, err)
		require.Equal(t, []byte("foobar"), data)
	}

	t.Run("using Listen", func(t *testing.T) {
		ln, err := quic.Listen(newUPDConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()

		connChan := make(chan quic.Connection, 1)
		go func() {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				t.Logf("failed to accept connection: %s", err)
				close(connChan)
				return
			}
			connChan <- conn
		}()

		const rtt = 400 * time.Millisecond
		start := time.Now()
		conn := handshakeWithRTT(t, ln.Addr(), getTLSClientConfig(), getQuicConfig(nil), rtt)
		serverConn := <-connChan
		if serverConn == nil {
			t.Fatal("serverConn is nil")
		}
		sendAndReceive(t, serverConn, conn)

		rtts := time.Since(start).Seconds() / rtt.Seconds()
		require.GreaterOrEqual(t, rtts, float64(2))
		require.Less(t, rtts, float64(3))
	})

	t.Run("using ListenEarly", func(t *testing.T) {
		ln, err := quic.ListenEarly(newUPDConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()

		connChan := make(chan quic.Connection, 1)
		go func() {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				t.Logf("failed to accept connection: %s", err)
				close(connChan)
				return
			}
			connChan <- conn
		}()

		const rtt = 400 * time.Millisecond
		start := time.Now()
		conn := handshakeWithRTT(t, ln.Addr(), getTLSClientConfig(), getQuicConfig(nil), rtt)
		serverConn := <-connChan
		if serverConn == nil {
			t.Fatal("serverConn is nil")
		}
		sendAndReceive(t, serverConn, conn)

		took := time.Since(start)
		rtts := float64(took) / float64(rtt)
		require.GreaterOrEqual(t, rtts, float64(1))
		require.Less(t, rtts, float64(2))
	})
}
