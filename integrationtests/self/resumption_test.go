package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type clientSessionCache struct {
	cache tls.ClientSessionCache

	gets chan<- string
	puts chan<- string
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
	c.gets <- sessionKey
	return session, ok
}

func (c *clientSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.cache.Put(sessionKey, cs)
	c.puts <- sessionKey
}

var _ = Describe("TLS session resumption", func() {
	It("uses session resumption", func() {
		server, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		gets := make(chan string, 100)
		puts := make(chan string, 100)
		cache := newClientSessionCache(tls.NewLRUClientSessionCache(10), gets, puts)
		tlsConf := getTLSClientConfig()
		tlsConf.ClientSessionCache = cache
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			tlsConf,
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		var sessionKey string
		Eventually(puts).Should(Receive(&sessionKey))
		Expect(conn.ConnectionState().TLS.DidResume).To(BeFalse())

		serverConn, err := server.Accept(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(serverConn.ConnectionState().TLS.DidResume).To(BeFalse())

		conn, err = quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			tlsConf,
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(gets).To(Receive(Equal(sessionKey)))
		Expect(conn.ConnectionState().TLS.DidResume).To(BeTrue())

		serverConn, err = server.Accept(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(serverConn.ConnectionState().TLS.DidResume).To(BeTrue())
	})

	It("doesn't use session resumption, if the config disables it", func() {
		sConf := getTLSConfig()
		sConf.SessionTicketsDisabled = true
		server, err := quic.ListenAddr("localhost:0", sConf, getQuicConfig(nil))
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		gets := make(chan string, 100)
		puts := make(chan string, 100)
		cache := newClientSessionCache(tls.NewLRUClientSessionCache(10), gets, puts)
		tlsConf := getTLSClientConfig()
		tlsConf.ClientSessionCache = cache
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			tlsConf,
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		Consistently(puts).ShouldNot(Receive())
		Expect(conn.ConnectionState().TLS.DidResume).To(BeFalse())

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		serverConn, err := server.Accept(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(serverConn.ConnectionState().TLS.DidResume).To(BeFalse())

		conn, err = quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			tlsConf,
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(conn.ConnectionState().TLS.DidResume).To(BeFalse())

		serverConn, err = server.Accept(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(serverConn.ConnectionState().TLS.DidResume).To(BeFalse())
	})

	It("doesn't use session resumption, if the config returned by GetConfigForClient disables it", func() {
		sConf := &tls.Config{
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				conf := getTLSConfig()
				conf.SessionTicketsDisabled = true
				return conf, nil
			},
		}

		server, err := quic.ListenAddr("localhost:0", sConf, getQuicConfig(nil))
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		gets := make(chan string, 100)
		puts := make(chan string, 100)
		cache := newClientSessionCache(tls.NewLRUClientSessionCache(10), gets, puts)
		tlsConf := getTLSClientConfig()
		tlsConf.ClientSessionCache = cache
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			tlsConf,
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		Consistently(puts).ShouldNot(Receive())
		Expect(conn.ConnectionState().TLS.DidResume).To(BeFalse())

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		serverConn, err := server.Accept(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(serverConn.ConnectionState().TLS.DidResume).To(BeFalse())

		conn, err = quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			tlsConf,
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(conn.ConnectionState().TLS.DidResume).To(BeFalse())

		serverConn, err = server.Accept(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(serverConn.ConnectionState().TLS.DidResume).To(BeFalse())
	})
})
