package self_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

func TestHandshakeRTTRetry(t *testing.T) {
	t.Run("retry", func(t *testing.T) {
		testHandshakeRTTRetry(t, true)
	})
	t.Run("no retry", func(t *testing.T) {
		testHandshakeRTTRetry(t, false)
	})
}

func testHandshakeRTTRetry(t *testing.T, doRetry bool) {
	var addrVerified bool
	rtts := testHandshakeMeasureHandshake(t,
		func(net.Addr) bool { return doRetry },
		getTLSConfig(),
		getQuicConfig(&quic.Config{
			GetConfigForClient: func(info *quic.ClientInfo) (*quic.Config, error) {
				addrVerified = info.AddrVerified
				return nil, nil
			},
		}),
	)
	if doRetry {
		require.True(t, addrVerified, "should have verified address")
		require.GreaterOrEqual(t, rtts, float64(2))
		require.Less(t, rtts, float64(2.1))
	} else {
		require.False(t, addrVerified, "should not have verified address")
		require.GreaterOrEqual(t, rtts, float64(1))
		require.Less(t, rtts, float64(1.1))
	}
}

func TestHandshakeRTTHelloRetryRequest(t *testing.T) {
	tlsConf := getTLSConfig()
	tlsConf.CurvePreferences = []tls.CurveID{tls.CurveP384}
	rtts := testHandshakeMeasureHandshake(t, nil, tlsConf, getQuicConfig(nil))
	require.GreaterOrEqual(t, rtts, float64(2))
	require.Less(t, rtts, float64(2.1))
}

func testHandshakeMeasureHandshake(t *testing.T, verifySourceAddress func(net.Addr) bool, tlsConf *tls.Config, quicConf *quic.Config) float64 {
	var rtts float64
	synctest.Test(t, func(t *testing.T) {
		const rtt = 100 * time.Millisecond

		clientPacketConn, serverPacketConn, close := newSimnetLink(t, rtt)
		defer close(t)

		tr := &quic.Transport{
			Conn:                serverPacketConn,
			VerifySourceAddress: verifySourceAddress,
		}
		addTracer(tr)
		defer tr.Close()
		ln, err := tr.Listen(tlsConf, quicConf)
		require.NoError(t, err)
		defer ln.Close()

		clientConfig := getQuicConfig(nil)
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 10*rtt)
		defer cancel()
		conn, err := quic.Dial(
			ctx,
			clientPacketConn,
			serverPacketConn.LocalAddr(),
			getTLSClientConfig(),
			clientConfig,
		)
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")

		rtts = time.Since(start).Seconds() / rtt.Seconds()
	})
	return rtts
}

func TestHandshake05RTT(t *testing.T) {
	t.Run("using ListenEarly", func(t *testing.T) {
		testHandshake05RTT(t, true)
	})
	t.Run("using Listen", func(t *testing.T) {
		testHandshake05RTT(t, false)
	})
}

func testHandshake05RTT(t *testing.T, use05RTT bool) {
	synctest.Test(t, func(t *testing.T) {
		type accepter interface {
			Accept(context.Context) (*quic.Conn, error)
		}

		const rtt = 100 * time.Millisecond
		clientPacketConn, serverPacketConn, close := newSimnetLink(t, rtt)
		defer close(t)
		var ln accepter
		if use05RTT {
			var err error
			server, err := quic.ListenEarly(serverPacketConn, getTLSConfig(), getQuicConfig(nil))
			require.NoError(t, err)
			defer server.Close()
			ln = server
		} else {
			var err error
			server, err := quic.Listen(serverPacketConn, getTLSConfig(), getQuicConfig(nil))
			require.NoError(t, err)
			defer server.Close()
			ln = server
		}

		connChan := make(chan *quic.Conn, 1)
		errChan := make(chan error, 1)
		go func() {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				errChan <- err
				return
			}
			str, err := conn.OpenUniStream()
			if err != nil {
				errChan <- err
				return
			}
			if _, err := str.Write([]byte("foobar")); err != nil {
				errChan <- err
				return
			}
			if err := str.Close(); err != nil {
				errChan <- err
				return
			}

			connChan <- conn
		}()

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 10*rtt)
		defer cancel()
		conn, err := quic.Dial(
			ctx,
			clientPacketConn,
			serverPacketConn.LocalAddr(),
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")

		rtts := time.Since(start).Seconds() / rtt.Seconds()
		require.GreaterOrEqual(t, rtts, float64(1))
		require.Less(t, rtts, float64(1.1))

		start = time.Now()

		select {
		case err := <-errChan:
			t.Fatal("failed to accept connection:", err)
		case conn := <-connChan:
			if !use05RTT {
				// the server finishes the handshake 0.5 RTTs later
				rtts = time.Since(start).Seconds() / rtt.Seconds()
				require.GreaterOrEqual(t, rtts, float64(0.5))
				require.Less(t, rtts, float64(0.6))
			}
			defer conn.CloseWithError(0, "")
		}

		// If 0.5 RTT was used, the message should be received immediately,
		// otherwise it should take 1 RTT.
		str, err := conn.AcceptUniStream(ctx)
		require.NoError(t, err)
		data, err := io.ReadAll(str)
		require.NoError(t, err)
		require.Equal(t, []byte("foobar"), data)

		rtts = time.Since(start).Seconds() / rtt.Seconds()
		if use05RTT {
			require.GreaterOrEqual(t, rtts, float64(0))
			require.Less(t, rtts, float64(0.1))
		} else {
			require.GreaterOrEqual(t, rtts, float64(1))
			require.Less(t, rtts, float64(1.1))
		}
	})
}
