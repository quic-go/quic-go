package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/israce"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type versioner interface {
	GetVersion() protocol.VersionNumber
}

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

var _ = Describe("Handshake tests", func() {
	var (
		server        quic.Listener
		serverConfig  *quic.Config
		acceptStopped chan struct{}
		tlsServerConf *tls.Config
	)

	BeforeEach(func() {
		server = nil
		acceptStopped = make(chan struct{})
		serverConfig = &quic.Config{}
		tlsServerConf = getTLSConfig()
	})

	AfterEach(func() {
		if server != nil {
			server.Close()
			<-acceptStopped
		}
	})

	runServer := func() quic.Listener {
		var err error
		// start the server
		server, err = quic.ListenAddr("localhost:0", tlsServerConf, serverConfig)
		Expect(err).ToNot(HaveOccurred())

		go func() {
			defer GinkgoRecover()
			defer close(acceptStopped)
			for {
				if _, err := server.Accept(context.Background()); err != nil {
					return
				}
			}
		}()
		return server
	}

	if !israce.Enabled {
		Context("Version Negotiation", func() {
			var supportedVersions []protocol.VersionNumber

			BeforeEach(func() {
				supportedVersions = protocol.SupportedVersions
				protocol.SupportedVersions = append(protocol.SupportedVersions, []protocol.VersionNumber{7, 8, 9, 10}...)
			})

			AfterEach(func() {
				protocol.SupportedVersions = supportedVersions
			})

			It("when the server supports more versions than the client", func() {
				// the server doesn't support the highest supported version, which is the first one the client will try
				// but it supports a bunch of versions that the client doesn't speak
				serverConfig.Versions = []protocol.VersionNumber{7, 8, protocol.SupportedVersions[0], 9}
				server := runServer()
				defer server.Close()
				sess, err := quic.DialAddr(
					fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
					getTLSClientConfig(),
					nil,
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(sess.(versioner).GetVersion()).To(Equal(protocol.SupportedVersions[0]))
				Expect(sess.Close()).To(Succeed())
			})

			It("when the client supports more versions than the server supports", func() {
				// the server doesn't support the highest supported version, which is the first one the client will try
				// but it supports a bunch of versions that the client doesn't speak
				serverConfig.Versions = supportedVersions
				server := runServer()
				defer server.Close()
				conf := &quic.Config{
					Versions: []protocol.VersionNumber{7, 8, 9, protocol.SupportedVersions[0], 10},
				}
				sess, err := quic.DialAddr(
					fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
					getTLSClientConfig(),
					conf,
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(sess.(versioner).GetVersion()).To(Equal(protocol.SupportedVersions[0]))
				Expect(sess.Close()).To(Succeed())
			})
		})
	}

	Context("Certifiate validation", func() {
		for _, v := range protocol.SupportedVersions {
			version := v

			Context(fmt.Sprintf("using %s", version), func() {
				var clientConfig *quic.Config

				BeforeEach(func() {
					serverConfig.Versions = []protocol.VersionNumber{version}
					clientConfig = &quic.Config{
						Versions: []protocol.VersionNumber{version},
					}
				})

				JustBeforeEach(func() {
					runServer()
				})

				It("accepts the certificate", func() {
					_, err := quic.DialAddr(
						fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
						getTLSClientConfig(),
						clientConfig,
					)
					Expect(err).ToNot(HaveOccurred())
				})

				It("errors if the server name doesn't match", func() {
					_, err := quic.DialAddr(
						fmt.Sprintf("127.0.0.1:%d", server.Addr().(*net.UDPAddr).Port),
						getTLSClientConfig(),
						clientConfig,
					)
					Expect(err).To(MatchError("CRYPTO_ERROR: x509: cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs"))
				})

				It("fails the handshake if the client fails to provide the requested client cert", func() {
					tlsServerConf.ClientAuth = tls.RequireAndVerifyClientCert
					sess, err := quic.DialAddr(
						fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
						getTLSClientConfig(),
						clientConfig,
					)
					// Usually, the error will occur after the client already finished the handshake.
					// However, there's a race condition here. The server's CONNECTION_CLOSE might be
					// received before the session is returned, so we might already get the error while dialing.
					if err == nil {
						errChan := make(chan error)
						go func() {
							defer GinkgoRecover()
							_, err := sess.AcceptStream(context.Background())
							errChan <- err
						}()
						Eventually(errChan).Should(Receive(&err))
					}
					Expect(err).To(MatchError("CRYPTO_ERROR: tls: bad certificate"))
				})

				It("uses the ServerName in the tls.Config", func() {
					tlsConf := getTLSClientConfig()
					tlsConf.ServerName = "localhost"
					_, err := quic.DialAddr(
						fmt.Sprintf("127.0.0.1:%d", server.Addr().(*net.UDPAddr).Port),
						tlsConf,
						clientConfig,
					)
					Expect(err).ToNot(HaveOccurred())
				})
			})
		}
	})

	Context("rate limiting", func() {
		var (
			server quic.Listener
			pconn  net.PacketConn
		)

		dial := func() (quic.Session, error) {
			remoteAddr := fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port)
			raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
			Expect(err).ToNot(HaveOccurred())
			return quic.Dial(
				pconn,
				raddr,
				remoteAddr,
				getTLSClientConfig(),
				nil,
			)
		}

		BeforeEach(func() {
			serverConfig.AcceptToken = func(addr net.Addr, token *quic.Token) bool {
				if token != nil {
					Expect(token.IsRetryToken).To(BeFalse())
				}
				return true
			}
			var err error
			// start the server, but don't call Accept
			server, err = quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
			Expect(err).ToNot(HaveOccurred())

			// prepare a (single) packet conn for dialing to the server
			laddr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			pconn, err = net.ListenUDP("udp", laddr)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			Expect(server.Close()).To(Succeed())
			Expect(pconn.Close()).To(Succeed())
		})

		It("rejects new connection attempts if connections don't get accepted", func() {
			for i := 0; i < protocol.MaxAcceptQueueSize; i++ {
				sess, err := dial()
				Expect(err).ToNot(HaveOccurred())
				defer sess.Close()
			}
			time.Sleep(25 * time.Millisecond) // wait a bit for the sessions to be queued

			_, err := dial()
			Expect(err).To(HaveOccurred())
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.ServerBusy))

			// now accept one session, freeing one spot in the queue
			_, err = server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			// dial again, and expect that this dial succeeds
			sess, err := dial()
			Expect(err).ToNot(HaveOccurred())
			defer sess.Close()
			time.Sleep(25 * time.Millisecond) // wait a bit for the session to be queued

			_, err = dial()
			Expect(err).To(HaveOccurred())
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.ServerBusy))
		})

		It("removes closed connections from the accept queue", func() {
			firstSess, err := dial()
			Expect(err).ToNot(HaveOccurred())

			for i := 1; i < protocol.MaxAcceptQueueSize; i++ {
				sess, err := dial()
				Expect(err).ToNot(HaveOccurred())
				defer sess.Close()
			}
			time.Sleep(25 * time.Millisecond) // wait a bit for the sessions to be queued

			_, err = dial()
			Expect(err).To(HaveOccurred())
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.ServerBusy))

			// Now close the one of the session that are waiting to be accepted.
			// This should free one spot in the queue.
			Expect(firstSess.Close())
			time.Sleep(25 * time.Millisecond)

			// dial again, and expect that this dial succeeds
			_, err = dial()
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(25 * time.Millisecond) // wait a bit for the session to be queued

			_, err = dial()
			Expect(err).To(HaveOccurred())
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.ServerBusy))
		})

	})

	Context("ALPN", func() {
		It("negotiates an application protocol", func() {
			ln, err := quic.ListenAddr("localhost:0", tlsServerConf, serverConfig)
			Expect(err).ToNot(HaveOccurred())

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				sess, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				cs := sess.ConnectionState()
				Expect(cs.NegotiatedProtocol).To(Equal(alpn))
				Expect(cs.NegotiatedProtocolIsMutual).To(BeTrue())
				close(done)
			}()

			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				nil,
			)
			Expect(err).ToNot(HaveOccurred())
			defer sess.Close()
			cs := sess.ConnectionState()
			Expect(cs.NegotiatedProtocol).To(Equal(alpn))
			Expect(cs.NegotiatedProtocolIsMutual).To(BeTrue())
			Eventually(done).Should(BeClosed())
			Expect(ln.Close()).To(Succeed())
		})

		It("errors if application protocol negotiation fails", func() {
			server := runServer()

			tlsConf := getTLSClientConfig()
			tlsConf.NextProtos = []string{"foobar"}
			_, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				tlsConf,
				nil,
			)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("CRYPTO_ERROR"))
			Expect(err.Error()).To(ContainSubstring("no application protocol"))
			Expect(server.Close()).To(Succeed())
		})
	})

	Context("using tokens", func() {
		It("uses tokens provided in NEW_TOKEN frames", func() {
			tokenChan := make(chan *quic.Token, 100)
			serverConfig.AcceptToken = func(addr net.Addr, token *quic.Token) bool {
				if token != nil && !token.IsRetryToken {
					tokenChan <- token
				}
				return true
			}

			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
			Expect(err).ToNot(HaveOccurred())

			// dial the first session and receive the token
			go func() {
				defer GinkgoRecover()
				_, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
			}()

			gets := make(chan string, 100)
			puts := make(chan string, 100)
			tokenStore := newTokenStore(gets, puts)
			quicConf := &quic.Config{TokenStore: tokenStore}
			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				quicConf,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(gets).To(Receive())
			Eventually(puts).Should(Receive())
			Expect(tokenChan).ToNot(Receive())
			// received a token. Close this session.
			Expect(sess.Close()).To(Succeed())

			// dial the second session and verify that the token was used
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				_, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
			}()
			sess, err = quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				quicConf,
			)
			Expect(err).ToNot(HaveOccurred())
			defer sess.Close()
			Expect(gets).To(Receive())
			Expect(tokenChan).To(Receive())

			Eventually(done).Should(BeClosed())
		})
	})
})
