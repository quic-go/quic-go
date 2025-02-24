package self_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/qtls"

	"github.com/stretchr/testify/require"
)

type tokenStore struct {
	store quic.TokenStore
	gets  chan<- string
	puts  chan<- string
}

var _ quic.TokenStore = &tokenStore{}

func newTokenStore(gets, puts chan<- string) quic.TokenStore {
	return &tokenStore{
		store: quic.NewLRUTokenStore(10, 4),
		gets:  gets,
		puts:  puts,
	}
}

func (c *tokenStore) Put(key string, token *quic.ClientToken) {
	c.puts <- key
	c.store.Put(key, token)
}

func (c *tokenStore) Pop(key string) *quic.ClientToken {
	c.gets <- key
	return c.store.Pop(key)
}

func TestHandshakeAddrResolutionHelpers(t *testing.T) {
	server, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.DialAddr(
		ctx,
		fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
		getTLSClientConfig(),
		getQuicConfig(nil),
	)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")
}

func TestHandshake(t *testing.T) {
	for _, tt := range []struct {
		name string
		conf *tls.Config
	}{
		{"short cert chain", getTLSConfig()},
		{"long cert chain", getTLSConfigWithLongCertChain()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, err := quic.Listen(newUDPConnLocalhost(t), tt.conf, getQuicConfig(nil))
			require.NoError(t, err)
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")

			serverConn, err := server.Accept(ctx)
			require.NoError(t, err)
			defer serverConn.CloseWithError(0, "")
		})
	}
}

func TestHandshakeServerMismatch(t *testing.T) {
	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	conf := getTLSClientConfig()
	conf.ServerName = "foo.bar"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(), conf, getQuicConfig(nil))
	require.Error(t, err)
	var transportErr *quic.TransportError
	require.True(t, errors.As(err, &transportErr))
	require.True(t, transportErr.ErrorCode.IsCryptoError())
	require.Contains(t, transportErr.Error(), "x509: certificate is valid for localhost, not foo.bar")
	var certErr *tls.CertificateVerificationError
	require.True(t, errors.As(transportErr, &certErr))
}

func TestHandshakeCipherSuites(t *testing.T) {
	for _, suiteID := range []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	} {
		t.Run(tls.CipherSuiteName(suiteID), func(t *testing.T) {
			reset := qtls.SetCipherSuite(suiteID)
			defer reset()

			ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
			require.NoError(t, err)
			defer ln.Close()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")

			serverConn, err := ln.Accept(context.Background())
			require.NoError(t, err)
			defer serverConn.CloseWithError(0, "")
			serverStr, err := serverConn.OpenStream()
			require.NoError(t, err)
			errChan := make(chan error, 1)
			go func() {
				defer serverStr.Close()
				_, err = serverStr.Write(PRData)
				errChan <- err
			}()
			require.NoError(t, <-errChan)

			str, err := conn.AcceptStream(context.Background())
			require.NoError(t, err)
			data, err := io.ReadAll(str)
			require.NoError(t, err)
			require.Equal(t, PRData, data)
			require.Equal(t, suiteID, conn.ConnectionState().TLS.CipherSuite)
		})
	}
}

func TestTLSGetConfigForClientError(t *testing.T) {
	tr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	addTracer(tr)
	defer tr.Close()

	tlsConf := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			return nil, errors.New("nope")
		},
	}
	ln, err := tr.Listen(tlsConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.True(t, transportErr.ErrorCode.IsCryptoError())
}

// Since we're not operating on a net.Conn, we need to jump through some hoops to set the addresses on the tls.ClientHelloInfo.
// Use a recursive setup to test that this works under all conditions.
func TestTLSConfigGetConfigForClientAddresses(t *testing.T) {
	var local, remote net.Addr
	var local2, remote2 net.Addr
	done := make(chan struct{})
	tlsConf := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			local = info.Conn.LocalAddr()
			remote = info.Conn.RemoteAddr()
			conf := getTLSConfig()
			conf.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				defer close(done)
				local2 = info.Conn.LocalAddr()
				remote2 = info.Conn.RemoteAddr()
				return &(conf.Certificates[0]), nil
			}
			return conf, nil
		},
	}
	server, err := quic.Listen(newUDPConnLocalhost(t), tlsConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for GetCertificate callback")
	}

	require.Equal(t, server.Addr(), local)
	require.Equal(t, conn.LocalAddr().(*net.UDPAddr).Port, remote.(*net.UDPAddr).Port)
	require.Equal(t, local, local2)
	require.Equal(t, remote, remote2)
}

func TestHandshakeFailsWithoutClientCert(t *testing.T) {
	tlsConf := getTLSConfig()
	tlsConf.ClientAuth = tls.RequireAndVerifyClientCert

	server, err := quic.Listen(newUDPConnLocalhost(t), tlsConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(), getTLSClientConfig(), getQuicConfig(nil))

	// Usually, the error will occur after the client already finished the handshake.
	// However, there's a race condition here. The server's CONNECTION_CLOSE might be
	// received before the connection is returned, so we might already get the error while dialing.
	if err == nil {
		errChan := make(chan error, 1)
		go func() {
			_, err := conn.AcceptStream(context.Background())
			errChan <- err
		}()

		err = <-errChan
	}

	require.Error(t, err)
	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.True(t, transportErr.ErrorCode.IsCryptoError())
	require.Condition(t, func() bool {
		errStr := transportErr.Error()
		return strings.Contains(errStr, "tls: certificate required") ||
			strings.Contains(errStr, "tls: bad certificate")
	})
}

func TestClosedConnectionsInAcceptQueue(t *testing.T) {
	dialer := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer dialer.Close()

	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Create first connection
	conn1, err := dialer.Dial(ctx, server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	conn2, err := dialer.Dial(ctx, server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn2.CloseWithError(0, "")
	// close the first connection
	const appErrCode quic.ApplicationErrorCode = 12345
	require.NoError(t, conn1.CloseWithError(appErrCode, ""))

	time.Sleep(scaleDuration(25 * time.Millisecond)) // wait for connections to be queued and closed

	// accept all connections, and find the closed one
	var closedConn quic.Connection
	for i := 0; i < 2; i++ {
		conn, err := server.Accept(ctx)
		require.NoError(t, err)
		if conn.Context().Err() != nil {
			require.Nil(t, closedConn, "only expected a single closed connection")
			closedConn = conn
		}
	}
	require.NotNil(t, closedConn, "expected one closed connection")

	_, err = closedConn.AcceptStream(context.Background())
	var appErr *quic.ApplicationError
	require.ErrorAs(t, err, &appErr)
	require.Equal(t, appErrCode, appErr.ErrorCode)
}

func TestServerAcceptQueueOverflow(t *testing.T) {
	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	dialer := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// fill up the accept queue
	for i := 0; i < protocol.MaxAcceptQueueSize; i++ {
		conn, err := dialer.Dial(ctx, server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
	}
	time.Sleep(scaleDuration(25 * time.Millisecond)) // wait for connections to be queued

	// next connection should be rejected
	conn, err := dialer.Dial(ctx, server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	_, err = conn.AcceptStream(ctx)
	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, quic.ConnectionRefused, transportErr.ErrorCode)

	// accept one connection to free up a spot
	_, err = server.Accept(ctx)
	require.NoError(t, err)

	// should be able to dial again
	conn2, err := dialer.Dial(ctx, server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn2.CloseWithError(0, "")
	time.Sleep(scaleDuration(25 * time.Millisecond))

	// but next connection should be rejected again
	conn3, err := dialer.Dial(ctx, server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	_, err = conn3.AcceptStream(ctx)
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, quic.ConnectionRefused, transportErr.ErrorCode)
}

func TestHandshakingConnectionsClosedOnServerShutdown(t *testing.T) {
	tr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	addTracer(tr)
	defer tr.Close()

	rtt := scaleDuration(40 * time.Millisecond)
	connQueued := make(chan struct{})
	tlsConf := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			close(connQueued)
			// Sleep for a bit.
			// This allows the server to close the connection before the handshake completes.
			time.Sleep(rtt / 2)
			return getTLSConfig(), nil
		},
	}

	ln, err := tr.Listen(tlsConf, getQuicConfig(nil))
	require.NoError(t, err)

	proxy := quicproxy.Proxy{
		Conn:        newUDPConnLocalhost(t),
		ServerAddr:  ln.Addr().(*net.UDPAddr),
		DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration { return rtt / 2 },
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	errChan := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		_, err := quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
		errChan <- err
	}()

	select {
	case <-connQueued:
	case <-time.After(5 * rtt):
		t.Fatal("timeout waiting for connection queued")
	}
	require.NoError(t, ln.Close())

	err = <-errChan
	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, quic.ConnectionRefused, transportErr.ErrorCode)
}

func TestALPN(t *testing.T) {
	ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	acceptChan := make(chan quic.Connection, 2)
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			acceptChan <- conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), nil)
	require.NoError(t, err)
	cs := conn.ConnectionState()
	require.Equal(t, alpn, cs.TLS.NegotiatedProtocol)

	select {
	case c := <-acceptChan:
		require.Equal(t, alpn, c.ConnectionState().TLS.NegotiatedProtocol)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for server connection")
	}
	require.NoError(t, conn.CloseWithError(0, ""))

	// now try with a different ALPN
	tlsConf := getTLSClientConfig()
	tlsConf.NextProtos = []string{"foobar"}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), tlsConf, nil)
	require.Error(t, err)
	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.True(t, transportErr.ErrorCode.IsCryptoError())
	require.Contains(t, transportErr.Error(), "no application protocol")
}

func TestTokensFromNewTokenFrames(t *testing.T) {
	t.Run("MaxTokenAge: 1 hour", func(t *testing.T) {
		testTokensFromNewTokenFrames(t, 0, true)
	})
	// If unset, the default value is 24h.
	t.Run("MaxTokenAge: default", func(t *testing.T) {
		testTokensFromNewTokenFrames(t, 0, true)
	})
	t.Run("MaxTokenAge: very short", func(t *testing.T) {
		testTokensFromNewTokenFrames(t, time.Microsecond, false)
	})
}

func testTokensFromNewTokenFrames(t *testing.T, maxTokenAge time.Duration, expectTokenUsed bool) {
	addrVerifiedChan := make(chan bool, 2)
	quicConf := getQuicConfig(nil)
	quicConf.GetConfigForClient = func(info *quic.ClientHelloInfo) (*quic.Config, error) {
		addrVerifiedChan <- info.AddrVerified
		return quicConf, nil
	}
	tr := &quic.Transport{Conn: newUDPConnLocalhost(t), MaxTokenAge: maxTokenAge}
	addTracer(tr)
	defer tr.Close()
	server, err := tr.Listen(getTLSConfig(), quicConf)
	require.NoError(t, err)
	defer server.Close()

	// dial the first connection and receive the token
	acceptChan := make(chan error, 2)
	go func() {
		_, err := server.Accept(context.Background())
		acceptChan <- err
		_, err = server.Accept(context.Background())
		acceptChan <- err
	}()

	gets := make(chan string, 2)
	puts := make(chan string, 2)
	ts := newTokenStore(gets, puts)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{TokenStore: ts}))
	require.NoError(t, err)

	// verify token store was used
	select {
	case <-gets:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for token store get")
	}
	select {
	case <-puts:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for token store put")
	}
	select {
	case addrVerified := <-addrVerifiedChan:
		require.False(t, addrVerified)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for addr verified")
	}
	select {
	case <-acceptChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for accept")
	}
	// received a token. Close this connection.
	require.NoError(t, conn.CloseWithError(0, ""))

	time.Sleep(scaleDuration(5 * time.Millisecond))
	conn, err = quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{TokenStore: ts}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	select {
	case addrVerified := <-addrVerifiedChan:
		// this time, the address was verified using the token
		if expectTokenUsed {
			require.True(t, addrVerified)
		} else {
			require.False(t, addrVerified)
		}

	case <-time.After(time.Second):
		t.Fatal("timeout waiting for addr verified")
	}
	select {
	case <-gets:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for token store get")
	}
	select {
	case <-acceptChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for accept")
	}
}

func TestInvalidToken(t *testing.T) {
	const rtt = 10 * time.Millisecond

	// The validity period of the retry token is the handshake timeout,
	// which is twice the handshake idle timeout.
	// By setting the handshake timeout shorter than the RTT, the token will have
	// expired by the time it reaches the server.
	serverConfig := getQuicConfig(&quic.Config{HandshakeIdleTimeout: rtt / 5})

	tr := &quic.Transport{
		Conn:                newUDPConnLocalhost(t),
		VerifySourceAddress: func(net.Addr) bool { return true },
	}
	addTracer(tr)
	defer tr.Close()

	server, err := tr.Listen(getTLSConfig(), serverConfig)
	require.NoError(t, err)
	defer server.Close()

	proxy := quicproxy.Proxy{
		Conn:        newUDPConnLocalhost(t),
		ServerAddr:  server.Addr().(*net.UDPAddr),
		DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration { return rtt / 2 },
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = quic.Dial(ctx, newUDPConnLocalhost(t), proxy.LocalAddr(), getTLSClientConfig(), nil)
	require.Error(t, err)
	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, quic.InvalidToken, transportErr.ErrorCode)
}

func TestGetConfigForClient(t *testing.T) {
	var calledFrom net.Addr
	serverConfig := getQuicConfig(&quic.Config{EnableDatagrams: true})
	serverConfig.GetConfigForClient = func(info *quic.ClientHelloInfo) (*quic.Config, error) {
		conf := serverConfig.Clone()
		conf.EnableDatagrams = true
		calledFrom = info.RemoteAddr
		return getQuicConfig(conf), nil
	}
	ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), serverConfig)
	require.NoError(t, err)

	acceptDone := make(chan struct{})
	go func() {
		_, err := ln.Accept(context.Background())
		require.NoError(t, err)
		close(acceptDone)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	cs := conn.ConnectionState()
	require.True(t, cs.SupportsDatagrams)

	select {
	case <-acceptDone:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for accept")
	}

	require.NoError(t, ln.Close())
	require.Equal(t, conn.LocalAddr().(*net.UDPAddr).Port, calledFrom.(*net.UDPAddr).Port)
}

func TestGetConfigForClientErrorsConnectionRejection(t *testing.T) {
	ln, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{
			GetConfigForClient: func(info *quic.ClientHelloInfo) (*quic.Config, error) {
				return nil, errors.New("rejected")
			},
		}),
	)
	require.NoError(t, err)

	acceptChan := make(chan bool, 1)
	go func() {
		_, err := ln.Accept(context.Background())
		acceptChan <- err == nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.ConnectionRefused, transportErr.ErrorCode)

	// verify no connection was accepted
	ln.Close()
	require.False(t, <-acceptChan)
}

func TestNoPacketsSentWhenClientHelloFails(t *testing.T) {
	conn := newUDPConnLocalhost(t)

	packetChan := make(chan struct{}, 1)
	go func() {
		for {
			_, _, err := conn.ReadFromUDP(make([]byte, protocol.MaxPacketBufferSize))
			if err != nil {
				return
			}
			select {
			case packetChan <- struct{}{}:
			default:
			}
		}
	}()

	tlsConf := getTLSClientConfig()
	tlsConf.NextProtos = []string{""}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := quic.Dial(ctx, newUDPConnLocalhost(t), conn.LocalAddr(), tlsConf, getQuicConfig(nil))

	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.True(t, transportErr.ErrorCode.IsCryptoError())
	require.Contains(t, err.Error(), "tls: invalid NextProtos value")

	// verify no packets were sent
	select {
	case <-packetChan:
		t.Fatal("received unexpected packet")
	case <-time.After(50 * time.Millisecond):
		// no packets received, as expected
	}
}
