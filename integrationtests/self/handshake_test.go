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

func TestHandshake(t *testing.T) {
	for _, tt := range []struct {
		name string
		conf *tls.Config
	}{
		{"short cert chain", getTLSConfig()},
		{"long cert chain", getTLSConfigWithLongCertChain()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, err := quic.ListenAddr("localhost:0", tt.conf, getQuicConfig(nil))
			require.NoError(t, err)
			defer server.Close()

			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")

			_, err = server.Accept(context.Background())
			require.NoError(t, err)
		})
	}
}

func TestHandshakeServerMismatch(t *testing.T) {
	server, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	conf := getTLSClientConfig()
	conf.ServerName = "foo.bar"
	_, err = quic.Dial(
		context.Background(),
		conn,
		server.Addr(),
		conf,
		getQuicConfig(nil),
	)
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

			ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
			require.NoError(t, err)
			defer ln.Close()

			go func() {
				conn, err := ln.Accept(context.Background())
				require.NoError(t, err)
				str, err := conn.OpenStream()
				require.NoError(t, err)
				defer str.Close()
				_, err = str.Write(PRData)
				require.NoError(t, err)
			}()

			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			require.NoError(t, err)
			str, err := conn.AcceptStream(context.Background())
			require.NoError(t, err)
			data, err := io.ReadAll(str)
			require.NoError(t, err)
			require.Equal(t, PRData, data)
			require.Equal(t, suiteID, conn.ConnectionState().TLS.CipherSuite)
			require.NoError(t, conn.CloseWithError(0, ""))
		})
	}
}

func TestTLSGetConfigForClientError(t *testing.T) {
	laddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	require.NoError(t, err)
	udpConn, err := net.ListenUDP("udp", laddr)
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udpConn}
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

	_, err = quic.DialAddr(context.Background(), ln.Addr().String(), getTLSClientConfig(), getQuicConfig(nil))
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
	server, err := quic.ListenAddr("localhost:0", tlsConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	conn, err := quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
		getTLSClientConfig(),
		getQuicConfig(nil),
	)
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

	server, err := quic.ListenAddr("localhost:0", tlsConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	conn, err := quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
		getTLSClientConfig(),
		getQuicConfig(nil),
	)

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
	laddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	require.NoError(t, err)
	pconn, err := net.ListenUDP("udp", laddr)
	require.NoError(t, err)
	defer pconn.Close()
	dialer := &quic.Transport{Conn: pconn}
	defer dialer.Close()

	server, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	raddr, err := net.ResolveUDPAddr("udp", server.Addr().String())
	require.NoError(t, err)

	// Create first connection
	conn1, err := dialer.Dial(context.Background(), raddr, getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	conn2, err := dialer.Dial(context.Background(), raddr, getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn2.CloseWithError(0, "")
	// close the first connection
	const appErrCode quic.ApplicationErrorCode = 12345
	require.NoError(t, conn1.CloseWithError(appErrCode, ""))

	time.Sleep(scaleDuration(25 * time.Millisecond)) // wait for connections to be queued and closed

	// accept all connections, and find the closed one
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
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
	server, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	laddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	require.NoError(t, err)
	pconn, err := net.ListenUDP("udp", laddr)
	require.NoError(t, err)
	defer pconn.Close()
	dialer := &quic.Transport{Conn: pconn}
	defer dialer.Close()

	remoteAddr := fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port)
	raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	require.NoError(t, err)

	// fill up the accept queue
	for i := 0; i < protocol.MaxAcceptQueueSize; i++ {
		conn, err := dialer.Dial(context.Background(), raddr, getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
	}
	time.Sleep(scaleDuration(25 * time.Millisecond)) // wait for connections to be queued

	// next connection should be rejected
	conn, err := dialer.Dial(context.Background(), raddr, getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err = conn.AcceptStream(ctx)
	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, quic.ConnectionRefused, transportErr.ErrorCode)

	// accept one connection to free up a spot
	_, err = server.Accept(context.Background())
	require.NoError(t, err)

	// should be able to dial again
	conn2, err := dialer.Dial(context.Background(), raddr, getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn2.CloseWithError(0, "")
	time.Sleep(scaleDuration(25 * time.Millisecond))

	// but next connection should be rejected again
	conn3, err := dialer.Dial(context.Background(), raddr, getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	_, err = conn3.AcceptStream(ctx)
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, quic.ConnectionRefused, transportErr.ErrorCode)
}

func TestHandshakingConnectionsClosedOnServerShutdown(t *testing.T) {
	laddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	require.NoError(t, err)
	udpConn, err := net.ListenUDP("udp", laddr)
	require.NoError(t, err)

	tr := &quic.Transport{Conn: udpConn}
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

	proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
		RemoteAddr:  fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
		DelayPacket: func(quicproxy.Direction, []byte) time.Duration { return rtt / 2 },
	})
	require.NoError(t, err)
	defer proxy.Close()

	errChan := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_, err := quic.DialAddr(ctx, ln.Addr().String(), getTLSClientConfig(), getQuicConfig(nil))
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
	ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
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

	conn, err := quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
		getTLSClientConfig(),
		nil,
	)
	require.NoError(t, err)
	cs := conn.ConnectionState()
	require.Equal(t, alpn, cs.TLS.NegotiatedProtocol)
	require.NoError(t, conn.CloseWithError(0, ""))

	select {
	case c := <-acceptChan:
		require.Equal(t, alpn, c.ConnectionState().TLS.NegotiatedProtocol)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for server connection")
	}

	// now try with a different ALPN
	tlsConf := getTLSClientConfig()
	tlsConf.NextProtos = []string{"foobar"}
	_, err = quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
		tlsConf,
		nil,
	)
	require.Error(t, err)
	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.True(t, transportErr.ErrorCode.IsCryptoError())
	require.Contains(t, transportErr.Error(), "no application protocol")
}

func TestTokensFromNewTokenFrames(t *testing.T) {
	addrVerifiedChan := make(chan bool, 2)
	quicConf := getQuicConfig(nil)
	quicConf.GetConfigForClient = func(info *quic.ClientHelloInfo) (*quic.Config, error) {
		addrVerifiedChan <- info.AddrVerified
		return quicConf, nil
	}
	server, err := quic.ListenAddr("localhost:0", getTLSConfig(), quicConf)
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
	tokenStore := newTokenStore(gets, puts)
	conn, err := quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{TokenStore: tokenStore}),
	)
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

	conn, err = quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{TokenStore: tokenStore}),
	)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	select {
	case addrVerified := <-addrVerifiedChan:
		// this time, the address was verified using the token
		// TODO (#4737): check that addrVerified is true
		_ = addrVerified
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

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer udpConn.Close()
	tr := &quic.Transport{
		Conn:                udpConn,
		VerifySourceAddress: func(net.Addr) bool { return true },
	}
	addTracer(tr)
	defer tr.Close()

	server, err := tr.Listen(getTLSConfig(), serverConfig)
	require.NoError(t, err)
	defer server.Close()

	serverPort := server.Addr().(*net.UDPAddr).Port
	proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
		RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
		DelayPacket: func(quicproxy.Direction, []byte) time.Duration {
			return rtt / 2
		},
	})
	require.NoError(t, err)
	defer proxy.Close()

	_, err = quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", proxy.LocalPort()),
		getTLSClientConfig(),
		nil,
	)
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
	ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
	require.NoError(t, err)

	acceptDone := make(chan struct{})
	go func() {
		_, err := ln.Accept(context.Background())
		require.NoError(t, err)
		close(acceptDone)
	}()

	conn, err := quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: true}),
	)
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
	ln, err := quic.ListenAddr(
		"localhost:0",
		getTLSConfig(),
		getQuicConfig(&quic.Config{
			EnableDatagrams: false,
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

	_, err = quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: true}),
	)
	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.ConnectionRefused, transportErr.ErrorCode)

	// verify no connection was accepted
	ln.Close()
	require.False(t, <-acceptChan)
}

func TestNoPacketsSentWhenClientHelloFails(t *testing.T) {
	ln, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	defer ln.Close()

	packetChan := make(chan struct{}, 1)
	go func() {
		for {
			_, _, err := ln.ReadFromUDP(make([]byte, protocol.MaxPacketBufferSize))
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
	_, err = quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", ln.LocalAddr().(*net.UDPAddr).Port),
		tlsConf,
		getQuicConfig(nil),
	)

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
