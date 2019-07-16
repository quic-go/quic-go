package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	quic "github.com/lucas-clemente/quic-go"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type clientSessionCache struct {
	mutex sync.Mutex
	cache map[string]*tls.ClientSessionState

	gets chan<- string
	puts chan<- string
}

func newClientSessionCache(gets, puts chan<- string) *clientSessionCache {
	return &clientSessionCache{
		cache: make(map[string]*tls.ClientSessionState),
		gets:  gets,
		puts:  puts,
	}
}

var _ tls.ClientSessionCache = &clientSessionCache{}

func (c *clientSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	c.gets <- sessionKey
	c.mutex.Lock()
	session, ok := c.cache[sessionKey]
	c.mutex.Unlock()
	return session, ok
}

func (c *clientSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.puts <- sessionKey
	c.mutex.Lock()
	c.cache[sessionKey] = cs
	c.mutex.Unlock()
}

var _ = Describe("TLS session resumption", func() {
	It("uses session resumption", func() {
		server, err := quic.ListenAddr("localhost:0", getTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		gets := make(chan string, 100)
		puts := make(chan string, 100)
		cache := newClientSessionCache(gets, puts)
		tlsConf := getTLSClientConfig()
		tlsConf.ClientSessionCache = cache
		sess, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			tlsConf,
			nil,
		)
		Expect(err).ToNot(HaveOccurred())
		var sessionKey string
		Eventually(puts).Should(Receive(&sessionKey))
		Expect(sess.ConnectionState().DidResume).To(BeFalse())

		serverSess, err := server.Accept(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(serverSess.ConnectionState().DidResume).To(BeFalse())

		sess, err = quic.DialAddr(
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			tlsConf,
			nil,
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(gets).To(Receive(Equal(sessionKey)))
		Expect(sess.ConnectionState().DidResume).To(BeTrue())

		serverSess, err = server.Accept(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(serverSess.ConnectionState().DidResume).To(BeTrue())
	})

	It("doesn't use session resumption, if the config disables it", func() {
		sConf := getTLSConfig()
		sConf.SessionTicketsDisabled = true
		server, err := quic.ListenAddr("localhost:0", sConf, nil)
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		gets := make(chan string, 100)
		puts := make(chan string, 100)
		cache := newClientSessionCache(gets, puts)
		tlsConf := getTLSClientConfig()
		tlsConf.ClientSessionCache = cache
		sess, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			tlsConf,
			nil,
		)
		Expect(err).ToNot(HaveOccurred())
		Consistently(puts).ShouldNot(Receive())
		Expect(sess.ConnectionState().DidResume).To(BeFalse())

		serverSess, err := server.Accept(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(serverSess.ConnectionState().DidResume).To(BeFalse())

		sess, err = quic.DialAddr(
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			tlsConf,
			nil,
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(sess.ConnectionState().DidResume).To(BeFalse())

		serverSess, err = server.Accept(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(serverSess.ConnectionState().DidResume).To(BeFalse())
	})
})
