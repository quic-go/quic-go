package self_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/synctest"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

type clientSessionCache struct {
	cache tls.ClientSessionCache
	gets  chan<- string
	puts  chan<- string
}

func newClientSessionCache(cache tls.ClientSessionCache, gets, puts chan<- string) *clientSessionCache {
	return &clientSessionCache{
		cache: cache,
		gets:  gets,
		puts:  puts,
	}
}

var _ tls.ClientSessionCache = &clientSessionCache{}

func (c *clientSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	session, ok := c.cache.Get(sessionKey)
	if c.gets != nil {
		c.gets <- sessionKey
	}
	return session, ok
}

func (c *clientSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.cache.Put(sessionKey, cs)
	if c.puts != nil {
		c.puts <- sessionKey
	}
}

func TestTLSSessionResumption(t *testing.T) {
	t.Run("uses session resumption", func(t *testing.T) {
		handshakeWithSessionResumption(t, getTLSConfig(), true)
	})

	t.Run("disabled in tls.Config", func(t *testing.T) {
		sConf := getTLSConfig()
		sConf.SessionTicketsDisabled = true
		handshakeWithSessionResumption(t, sConf, false)
	})

	t.Run("disabled in tls.Config.GetConfigForClient", func(t *testing.T) {
		sConf := &tls.Config{
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				conf := getTLSConfig()
				conf.SessionTicketsDisabled = true
				return conf, nil
			},
		}
		handshakeWithSessionResumption(t, sConf, false)
	})
}

func handshakeWithSessionResumption(t *testing.T, serverTLSConf *tls.Config, expectSessionTicket bool) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 10 * time.Millisecond

		n := &simnet.Simnet{Router: &simnet.PerfectRouter{}}
		defer n.Close()
		settings := simnet.NodeBiDiLinkSettings{Latency: rtt / 2}
		clientPacketConn1 := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}, settings)
		defer clientPacketConn1.Close()
		clientPacketConn2 := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9001}, settings)
		defer clientPacketConn2.Close()
		serverPacketConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.3"), Port: 9002}, settings)
		defer serverPacketConn.Close()

		require.NoError(t, n.Start())

		server, err := quic.Listen(serverPacketConn, serverTLSConf, getQuicConfig(nil))
		require.NoError(t, err)
		defer server.Close()

		gets := make(chan string, 100)
		puts := make(chan string, 100)
		cache := newClientSessionCache(tls.NewLRUClientSessionCache(10), gets, puts)
		tlsConf := getTLSClientConfig()
		tlsConf.ClientSessionCache = cache

		// first connection - doesn't use resumption
		conn1, err := quic.Dial(context.Background(), clientPacketConn1, server.Addr(), tlsConf, getQuicConfig(nil))
		require.NoError(t, err)
		defer conn1.CloseWithError(0, "")
		require.False(t, conn1.ConnectionState().TLS.DidResume)

		var sessionKey string
		select {
		case sessionKey = <-puts:
			if !expectSessionTicket {
				t.Fatal("unexpected session ticket")
			}
		case <-time.After(time.Hour):
			if expectSessionTicket {
				t.Fatal("timeout waiting for session ticket")
			}
		}

		serverConn1, err := server.Accept(context.Background())
		require.NoError(t, err)
		require.False(t, serverConn1.ConnectionState().TLS.DidResume)
		defer serverConn1.CloseWithError(0, "")

		// second connection - will use resumption, if enabled
		conn2, err := quic.Dial(context.Background(), clientPacketConn2, server.Addr(), tlsConf, getQuicConfig(nil))
		require.NoError(t, err)
		defer conn2.CloseWithError(0, "")

		select {
		case k := <-gets:
			if expectSessionTicket {
				// we can only perform this check if we got a session ticket before
				require.Equal(t, sessionKey, k)
			}
		case <-time.After(time.Hour):
			if expectSessionTicket {
				t.Fatal("timeout waiting for retrieval of session ticket")
			}
		}

		serverConn2, err := server.Accept(context.Background())
		require.NoError(t, err)
		defer serverConn2.CloseWithError(0, "")

		if expectSessionTicket {
			require.True(t, conn2.ConnectionState().TLS.DidResume)
			require.True(t, serverConn2.ConnectionState().TLS.DidResume)
		} else {
			require.False(t, conn2.ConnectionState().TLS.DidResume)
			require.False(t, serverConn2.ConnectionState().TLS.DidResume)
		}
	})
}
