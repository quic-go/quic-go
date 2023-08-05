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
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/qtls"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

var _ = Describe("Handshake tests", func() {
	var (
		server        *quic.Listener
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

	Context("using different cipher suites", func() {
		for n, id := range map[string]uint16{
			"TLS_AES_128_GCM_SHA256":       tls.TLS_AES_128_GCM_SHA256,
			"TLS_AES_256_GCM_SHA384":       tls.TLS_AES_256_GCM_SHA384,
			"TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256,
		} {
			name := n
			suiteID := id

			It(fmt.Sprintf("using %s", name), func() {
				reset := qtls.SetCipherSuite(suiteID)
				defer reset()

				tlsConf := getTLSConfig()
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
					context.Background(),
					fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
					getTLSClientConfig(),
					getQuicConfig(nil),
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
		It("accepts the certificate", func() {
			runServer(getTLSConfig())
			_, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			Expect(err).ToNot(HaveOccurred())
		})

		It("has the right local and remote address on the tls.Config.GetConfigForClient ClientHelloInfo.Conn", func() {
			var local, remote net.Addr
			done := make(chan struct{})
			tlsConf := &tls.Config{
				GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
					defer close(done)
					local = info.Conn.LocalAddr()
					remote = info.Conn.RemoteAddr()
					return getTLSConfig(), nil
				},
			}
			runServer(tlsConf)
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			Expect(err).ToNot(HaveOccurred())
			Eventually(done).Should(BeClosed())
			Expect(server.Addr()).To(Equal(local))
			Expect(conn.LocalAddr().(*net.UDPAddr).Port).To(Equal(remote.(*net.UDPAddr).Port))
		})

		It("has the right local and remote address on the tls.Config.GetCertificate ClientHelloInfo.Conn", func() {
			var local, remote net.Addr
			done := make(chan struct{})
			tlsConf := getTLSConfig()
			tlsConf.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				defer close(done)
				local = info.Conn.LocalAddr()
				remote = info.Conn.RemoteAddr()
				cert := tlsConf.Certificates[0]
				return &cert, nil
			}
			runServer(tlsConf)
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			Expect(err).ToNot(HaveOccurred())
			Eventually(done).Should(BeClosed())
			Expect(server.Addr()).To(Equal(local))
			Expect(conn.LocalAddr().(*net.UDPAddr).Port).To(Equal(remote.(*net.UDPAddr).Port))
		})

		It("works with a long certificate chain", func() {
			runServer(getTLSConfigWithLongCertChain())
			_, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors if the server name doesn't match", func() {
			runServer(getTLSConfig())
			conn, err := net.ListenUDP("udp", nil)
			Expect(err).ToNot(HaveOccurred())
			conf := getTLSClientConfig()
			conf.ServerName = "foo.bar"
			_, err = quic.Dial(
				context.Background(),
				conn,
				server.Addr(),
				conf,
				getQuicConfig(nil),
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
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(nil),
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
			Expect(transportErr.Error()).To(Or(
				ContainSubstring("tls: certificate required"),
				ContainSubstring("tls: bad certificate"),
			))
		})

		It("uses the ServerName in the tls.Config", func() {
			runServer(getTLSConfig())
			tlsConf := getTLSClientConfig()
			tlsConf.ServerName = "foo.bar"
			_, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				tlsConf,
				getQuicConfig(nil),
			)
			Expect(err).To(HaveOccurred())
			var transportErr *quic.TransportError
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode.IsCryptoError()).To(BeTrue())
			Expect(transportErr.Error()).To(ContainSubstring("x509: certificate is valid for localhost, not foo.bar"))
		})
	})

	Context("rate limiting", func() {
		var (
			server *quic.Listener
			pconn  net.PacketConn
			dialer *quic.Transport
		)

		dial := func() (quic.Connection, error) {
			remoteAddr := fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port)
			raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
			Expect(err).ToNot(HaveOccurred())
			return dialer.Dial(context.Background(), raddr, getTLSClientConfig(), getQuicConfig(nil))
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
			dialer = &quic.Transport{Conn: pconn, ConnectionIDLength: 4}
		})

		AfterEach(func() {
			Expect(server.Close()).To(Succeed())
			Expect(pconn.Close()).To(Succeed())
			Expect(dialer.Close()).To(Succeed())
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
			time.Sleep(scaleDuration(200 * time.Millisecond))

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
				context.Background(),
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
				context.Background(),
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
			defer server.Close()

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
				context.Background(),
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
				context.Background(),
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
				context.Background(),
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

	Context("GetConfigForClient", func() {
		It("uses the quic.Config returned by GetConfigForClient", func() {
			serverConfig.EnableDatagrams = false
			var calledFrom net.Addr
			serverConfig.GetConfigForClient = func(info *quic.ClientHelloInfo) (*quic.Config, error) {
				conf := serverConfig.Clone()
				conf.EnableDatagrams = true
				calledFrom = info.RemoteAddr
				return getQuicConfig(conf), nil
			}
			ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
			Expect(err).ToNot(HaveOccurred())

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()

			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{EnableDatagrams: true}),
			)
			Expect(err).ToNot(HaveOccurred())
			defer conn.CloseWithError(0, "")
			cs := conn.ConnectionState()
			Expect(cs.SupportsDatagrams).To(BeTrue())
			Eventually(done).Should(BeClosed())
			Expect(ln.Close()).To(Succeed())
			Expect(calledFrom.(*net.UDPAddr).Port).To(Equal(conn.LocalAddr().(*net.UDPAddr).Port))
		})

		It("rejects the connection attempt if GetConfigForClient errors", func() {
			serverConfig.EnableDatagrams = false
			serverConfig.GetConfigForClient = func(info *quic.ClientHelloInfo) (*quic.Config, error) {
				return nil, errors.New("rejected")
			}
			ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := ln.Accept(context.Background())
				Expect(err).To(HaveOccurred()) // we don't expect to accept any connection
				close(done)
			}()

			_, err = quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{EnableDatagrams: true}),
			)
			Expect(err).To(HaveOccurred())
			var transportErr *quic.TransportError
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode).To(Equal(qerr.ConnectionRefused))
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
			context.Background(),
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
