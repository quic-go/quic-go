package self_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/integrationtests/tools/israce"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
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

type versionNegotiationTracer struct {
	logging.NullConnectionTracer

	loggedVersions                 bool
	receivedVersionNegotiation     bool
	chosen                         logging.VersionNumber
	clientVersions, serverVersions []logging.VersionNumber
}

var _ logging.ConnectionTracer = &versionNegotiationTracer{}

func (t *versionNegotiationTracer) NegotiatedVersion(chosen logging.VersionNumber, clientVersions, serverVersions []logging.VersionNumber) {
	if t.loggedVersions {
		Fail("only expected one call to NegotiatedVersions")
	}
	t.loggedVersions = true
	t.chosen = chosen
	t.clientVersions = clientVersions
	t.serverVersions = serverVersions
}

func (t *versionNegotiationTracer) ReceivedVersionNegotiationPacket(dest, src logging.ArbitraryLenConnectionID, _ []logging.VersionNumber) {
	t.receivedVersionNegotiation = true
}

var _ = Describe("Handshake tests", func() {
	var (
		server        quic.Listener
		serverConfig  *quic.Config
		acceptStopped chan struct{}
	)

	BeforeEach(func() {
		server = nil
		acceptStopped = make(chan struct{})
		serverConfig = getQuicConfig(nil)
	})

	AfterEach(func() {
		if server != nil {
			server.Close()
			<-acceptStopped
		}
	})

	runServer := func(tlsConf *tls.Config) {
		var err error
		// start the server
		server, err = quic.ListenAddr("localhost:0", tlsConf, serverConfig)
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
				expectedVersion := protocol.SupportedVersions[0]
				// the server doesn't support the highest supported version, which is the first one the client will try
				// but it supports a bunch of versions that the client doesn't speak
				serverConfig.Versions = []protocol.VersionNumber{7, 8, protocol.SupportedVersions[0], 9}
				serverTracer := &versionNegotiationTracer{}
				serverConfig.Tracer = newTracer(func() logging.ConnectionTracer { return serverTracer })
				runServer(getTLSConfig())
				defer server.Close()
				clientTracer := &versionNegotiationTracer{}
				conn, err := quic.DialAddr(
					fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
					getTLSClientConfig(),
					getQuicConfig(&quic.Config{Tracer: newTracer(func() logging.ConnectionTracer { return clientTracer })}),
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(conn.(versioner).GetVersion()).To(Equal(expectedVersion))
				Expect(conn.CloseWithError(0, "")).To(Succeed())
				Expect(clientTracer.chosen).To(Equal(expectedVersion))
				Expect(clientTracer.receivedVersionNegotiation).To(BeFalse())
				Expect(clientTracer.clientVersions).To(Equal(protocol.SupportedVersions))
				Expect(clientTracer.serverVersions).To(BeEmpty())
				Expect(serverTracer.chosen).To(Equal(expectedVersion))
				Expect(serverTracer.serverVersions).To(Equal(serverConfig.Versions))
				Expect(serverTracer.clientVersions).To(BeEmpty())
			})

			It("when the client supports more versions than the server supports", func() {
				expectedVersion := protocol.SupportedVersions[0]
				// the server doesn't support the highest supported version, which is the first one the client will try
				// but it supports a bunch of versions that the client doesn't speak
				serverConfig.Versions = supportedVersions
				serverTracer := &versionNegotiationTracer{}
				serverConfig.Tracer = newTracer(func() logging.ConnectionTracer { return serverTracer })
				runServer(getTLSConfig())
				defer server.Close()
				clientVersions := []protocol.VersionNumber{7, 8, 9, protocol.SupportedVersions[0], 10}
				clientTracer := &versionNegotiationTracer{}
				conn, err := quic.DialAddr(
					fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
					getTLSClientConfig(),
					getQuicConfig(&quic.Config{
						Versions: clientVersions,
						Tracer:   newTracer(func() logging.ConnectionTracer { return clientTracer }),
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(conn.(versioner).GetVersion()).To(Equal(protocol.SupportedVersions[0]))
				Expect(conn.CloseWithError(0, "")).To(Succeed())
				Expect(clientTracer.chosen).To(Equal(expectedVersion))
				Expect(clientTracer.receivedVersionNegotiation).To(BeTrue())
				Expect(clientTracer.clientVersions).To(Equal(clientVersions))
				Expect(clientTracer.serverVersions).To(ContainElements(supportedVersions)) // may contain greased versions
				Expect(serverTracer.chosen).To(Equal(expectedVersion))
				Expect(serverTracer.serverVersions).To(Equal(serverConfig.Versions))
				Expect(serverTracer.clientVersions).To(BeEmpty())
			})
		})
	}

	Context("using different cipher suites", func() {
		for n, id := range map[string]uint16{
			"TLS_AES_128_GCM_SHA256":       tls.TLS_AES_128_GCM_SHA256,
			"TLS_AES_256_GCM_SHA384":       tls.TLS_AES_256_GCM_SHA384,
			"TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256,
		} {
			name := n
			suiteID := id

			It(fmt.Sprintf("using %s", name), func() {
				tlsConf := getTLSConfig()
				tlsConf.CipherSuites = []uint16{suiteID}
				ln, err := quic.ListenAddr("localhost:0", tlsConf, serverConfig)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()

				go func() {
					defer GinkgoRecover()
					conn, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := conn.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					defer str.Close()
					_, err = str.Write(PRData)
					Expect(err).ToNot(HaveOccurred())
				}()

				conn, err := quic.DialAddr(
					fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
					getTLSClientConfig(),
					nil,
				)
				Expect(err).ToNot(HaveOccurred())
				str, err := conn.AcceptStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				data, err := io.ReadAll(str)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal(PRData))
				Expect(conn.ConnectionState().TLS.CipherSuite).To(Equal(suiteID))
				Expect(conn.CloseWithError(0, "")).To(Succeed())
			})
		}
	})

	Context("Certificate validation", func() {
		for _, v := range protocol.SupportedVersions {
			version := v

			Context(fmt.Sprintf("using %s", version), func() {
				var clientConfig *quic.Config

				BeforeEach(func() {
					serverConfig.Versions = []protocol.VersionNumber{version}
					clientConfig = getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}})
				})

				It("accepts the certificate", func() {
					runServer(getTLSConfig())
					_, err := quic.DialAddr(
						fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
						getTLSClientConfig(),
						clientConfig,
					)
					Expect(err).ToNot(HaveOccurred())
				})

				It("works with a long certificate chain", func() {
					runServer(getTLSConfigWithLongCertChain())
					_, err := quic.DialAddr(
						fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
						getTLSClientConfig(),
						getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}),
					)
					Expect(err).ToNot(HaveOccurred())
				})

				It("errors if the server name doesn't match", func() {
					runServer(getTLSConfig())
					conn, err := net.ListenUDP("udp", nil)
					Expect(err).ToNot(HaveOccurred())
					_, err = quic.Dial(
						conn,
						server.Addr(),
						"foo.bar",
						getTLSClientConfig(),
						clientConfig,
					)
					Expect(err).To(HaveOccurred())
					var transportErr *quic.TransportError
					Expect(errors.As(err, &transportErr)).To(BeTrue())
					Expect(transportErr.ErrorCode.IsCryptoError()).To(BeTrue())
					Expect(transportErr.Error()).To(ContainSubstring("x509: certificate is valid for localhost, not foo.bar"))
				})

				It("fails the handshake if the client fails to provide the requested client cert", func() {
					tlsConf := getTLSConfig()
					tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
					runServer(tlsConf)

					conn, err := quic.DialAddr(
						fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
						getTLSClientConfig(),
						clientConfig,
					)
					// Usually, the error will occur after the client already finished the handshake.
					// However, there's a race condition here. The server's CONNECTION_CLOSE might be
					// received before the connection is returned, so we might already get the error while dialing.
					if err == nil {
						errChan := make(chan error)
						go func() {
							defer GinkgoRecover()
							_, err := conn.AcceptStream(context.Background())
							errChan <- err
						}()
						Eventually(errChan).Should(Receive(&err))
					}
					Expect(err).To(HaveOccurred())
					var transportErr *quic.TransportError
					Expect(errors.As(err, &transportErr)).To(BeTrue())
					Expect(transportErr.ErrorCode.IsCryptoError()).To(BeTrue())
					Expect(transportErr.Error()).To(ContainSubstring("tls: bad certificate"))
				})

				It("uses the ServerName in the tls.Config", func() {
					runServer(getTLSConfig())
					tlsConf := getTLSClientConfig()
					tlsConf.ServerName = "foo.bar"
					_, err := quic.DialAddr(
						fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
						tlsConf,
						clientConfig,
					)
					Expect(err).To(HaveOccurred())
					var transportErr *quic.TransportError
					Expect(errors.As(err, &transportErr)).To(BeTrue())
					Expect(transportErr.ErrorCode.IsCryptoError()).To(BeTrue())
					Expect(transportErr.Error()).To(ContainSubstring("x509: certificate is valid for localhost, not foo.bar"))
				})
			})
		}
	})

	Context("rate limiting", func() {
		var (
			server quic.Listener
			pconn  net.PacketConn
		)

		dial := func() (quic.Connection, error) {
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
				conn, err := dial()
				Expect(err).ToNot(HaveOccurred())
				defer conn.CloseWithError(0, "")
			}
			time.Sleep(25 * time.Millisecond) // wait a bit for the connection to be queued

			_, err := dial()
			Expect(err).To(HaveOccurred())
			var transportErr *quic.TransportError
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode).To(Equal(quic.ConnectionRefused))

			// now accept one connection, freeing one spot in the queue
			_, err = server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			// dial again, and expect that this dial succeeds
			conn, err := dial()
			Expect(err).ToNot(HaveOccurred())
			defer conn.CloseWithError(0, "")
			time.Sleep(25 * time.Millisecond) // wait a bit for the connection to be queued

			_, err = dial()
			Expect(err).To(HaveOccurred())
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode).To(Equal(quic.ConnectionRefused))
		})

		It("removes closed connections from the accept queue", func() {
			firstConn, err := dial()
			Expect(err).ToNot(HaveOccurred())

			for i := 1; i < protocol.MaxAcceptQueueSize; i++ {
				conn, err := dial()
				Expect(err).ToNot(HaveOccurred())
				defer conn.CloseWithError(0, "")
			}
			time.Sleep(scaleDuration(20 * time.Millisecond)) // wait a bit for the connection to be queued

			_, err = dial()
			Expect(err).To(HaveOccurred())
			var transportErr *quic.TransportError
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode).To(Equal(quic.ConnectionRefused))

			// Now close the one of the connection that are waiting to be accepted.
			// This should free one spot in the queue.
			Expect(firstConn.CloseWithError(0, ""))
			Eventually(firstConn.Context().Done()).Should(BeClosed())
			time.Sleep(scaleDuration(20 * time.Millisecond))

			// dial again, and expect that this dial succeeds
			_, err = dial()
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(scaleDuration(20 * time.Millisecond)) // wait a bit for the connection to be queued

			_, err = dial()
			Expect(err).To(HaveOccurred())
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode).To(Equal(quic.ConnectionRefused))
		})
	})

	Context("ALPN", func() {
		It("negotiates an application protocol", func() {
			ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
			Expect(err).ToNot(HaveOccurred())

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				conn, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				cs := conn.ConnectionState()
				Expect(cs.TLS.NegotiatedProtocol).To(Equal(alpn))
				close(done)
			}()

			conn, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				nil,
			)
			Expect(err).ToNot(HaveOccurred())
			defer conn.CloseWithError(0, "")
			cs := conn.ConnectionState()
			Expect(cs.TLS.NegotiatedProtocol).To(Equal(alpn))
			Eventually(done).Should(BeClosed())
			Expect(ln.Close()).To(Succeed())
		})

		It("errors if application protocol negotiation fails", func() {
			runServer(getTLSConfig())

			tlsConf := getTLSClientConfig()
			tlsConf.NextProtos = []string{"foobar"}
			_, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				tlsConf,
				nil,
			)
			Expect(err).To(HaveOccurred())
			var transportErr *quic.TransportError
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode.IsCryptoError()).To(BeTrue())
			Expect(transportErr.Error()).To(ContainSubstring("no application protocol"))
		})
	})

	Context("using tokens", func() {
		It("uses tokens provided in NEW_TOKEN frames", func() {
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
			Expect(err).ToNot(HaveOccurred())

			// dial the first connection and receive the token
			go func() {
				defer GinkgoRecover()
				_, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
			}()

			gets := make(chan string, 100)
			puts := make(chan string, 100)
			tokenStore := newTokenStore(gets, puts)
			quicConf := getQuicConfig(&quic.Config{TokenStore: tokenStore})
			conn, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				quicConf,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(gets).To(Receive())
			Eventually(puts).Should(Receive())
			// received a token. Close this connection.
			Expect(conn.CloseWithError(0, "")).To(Succeed())

			// dial the second connection and verify that the token was used
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				_, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
			}()
			conn, err = quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				quicConf,
			)
			Expect(err).ToNot(HaveOccurred())
			defer conn.CloseWithError(0, "")
			Expect(gets).To(Receive())

			Eventually(done).Should(BeClosed())
		})

		It("rejects invalid Retry token with the INVALID_TOKEN error", func() {
			serverConfig.RequireAddressValidation = func(net.Addr) bool { return true }
			serverConfig.MaxRetryTokenAge = time.Nanosecond

			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
			Expect(err).ToNot(HaveOccurred())
			defer server.Close()

			_, err = quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				nil,
			)
			Expect(err).To(HaveOccurred())
			var transportErr *quic.TransportError
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode).To(Equal(quic.InvalidToken))
		})
	})

	It("doesn't send any packets when generating the ClientHello fails", func() {
		ln, err := net.ListenUDP("udp", nil)
		Expect(err).ToNot(HaveOccurred())
		done := make(chan struct{})
		packetChan := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			for {
				_, _, err := ln.ReadFromUDP(make([]byte, protocol.MaxPacketBufferSize))
				if err != nil {
					return
				}
				packetChan <- struct{}{}
			}
		}()

		tlsConf := getTLSClientConfig()
		tlsConf.NextProtos = []string{""}
		_, err = quic.DialAddr(
			fmt.Sprintf("localhost:%d", ln.LocalAddr().(*net.UDPAddr).Port),
			tlsConf,
			nil,
		)
		Expect(err).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: "tls: invalid NextProtos value",
		}))
		Consistently(packetChan).ShouldNot(Receive())
		ln.Close()
		Eventually(done).Should(BeClosed())
	})
})
