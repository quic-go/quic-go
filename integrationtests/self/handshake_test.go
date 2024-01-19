package self_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/qtls"
	"github.com/quic-go/quic-go/logging"

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

	It("returns the context cancellation error on timeouts", func() {
		ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(20*time.Millisecond))
		defer cancel()
		errChan := make(chan error, 1)
		go func() {
			_, err := quic.DialAddr(
				ctx,
				"localhost:1234", // nobody is listening on this port, but we're going to cancel this dial anyway
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			errChan <- err
		}()

		var err error
		Eventually(errChan).Should(Receive(&err))
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(context.DeadlineExceeded))
	})

	It("returns the cancellation reason when a dial is canceled", func() {
		ctx, cancel := context.WithCancelCause(context.Background())
		errChan := make(chan error, 1)
		go func() {
			_, err := quic.DialAddr(
				ctx,
				"localhost:1234", // nobody is listening on this port, but we're going to cancel this dial anyway
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			errChan <- err
		}()

		cancel(errors.New("application cancelled"))
		var err error
		Eventually(errChan).Should(Receive(&err))
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError("application cancelled"))
	})

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
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			Expect(err).ToNot(HaveOccurred())
			conn.CloseWithError(0, "")
		})

		It("has the right local and remote address on the tls.Config.GetConfigForClient ClientHelloInfo.Conn", func() {
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
			runServer(tlsConf)
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			Expect(err).ToNot(HaveOccurred())
			defer conn.CloseWithError(0, "")
			Eventually(done).Should(BeClosed())
			Expect(server.Addr()).To(Equal(local))
			Expect(conn.LocalAddr().(*net.UDPAddr).Port).To(Equal(remote.(*net.UDPAddr).Port))
			Expect(local).To(Equal(local2))
			Expect(remote).To(Equal(remote2))
		})

		It("works with a long certificate chain", func() {
			runServer(getTLSConfigWithLongCertChain())
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			Expect(err).ToNot(HaveOccurred())
			conn.CloseWithError(0, "")
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
			var certErr *tls.CertificateVerificationError
			Expect(errors.As(transportErr, &certErr)).To(BeTrue())
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

	Context("queuening and accepting connections", func() {
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

			conn, err := dial()
			Expect(err).ToNot(HaveOccurred())
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_, err = conn.AcceptStream(ctx)
			var transportErr *quic.TransportError
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode).To(Equal(quic.ConnectionRefused))

			// now accept one connection, freeing one spot in the queue
			_, err = server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			// dial again, and expect that this dial succeeds
			conn2, err := dial()
			Expect(err).ToNot(HaveOccurred())
			defer conn2.CloseWithError(0, "")
			time.Sleep(25 * time.Millisecond) // wait a bit for the connection to be queued

			conn3, err := dial()
			Expect(err).ToNot(HaveOccurred())
			ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_, err = conn3.AcceptStream(ctx)
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode).To(Equal(quic.ConnectionRefused))
		})

		It("also returns closed connections from the accept queue", func() {
			firstConn, err := dial()
			Expect(err).ToNot(HaveOccurred())

			for i := 1; i < protocol.MaxAcceptQueueSize; i++ {
				conn, err := dial()
				Expect(err).ToNot(HaveOccurred())
				defer conn.CloseWithError(0, "")
			}
			time.Sleep(scaleDuration(20 * time.Millisecond)) // wait a bit for the connection to be queued

			conn, err := dial()
			Expect(err).ToNot(HaveOccurred())
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_, err = conn.AcceptStream(ctx)
			var transportErr *quic.TransportError
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode).To(Equal(quic.ConnectionRefused))

			// Now close the one of the connection that are waiting to be accepted.
			const appErrCode quic.ApplicationErrorCode = 12345
			Expect(firstConn.CloseWithError(appErrCode, ""))
			Eventually(firstConn.Context().Done()).Should(BeClosed())
			time.Sleep(scaleDuration(200 * time.Millisecond))

			// dial again, and expect that this fails again
			conn2, err := dial()
			Expect(err).ToNot(HaveOccurred())
			ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_, err = conn2.AcceptStream(ctx)
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode).To(Equal(quic.ConnectionRefused))

			// now accept all connections
			var closedConn quic.Connection
			for i := 0; i < protocol.MaxAcceptQueueSize; i++ {
				conn, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				if conn.Context().Err() != nil {
					if closedConn != nil {
						Fail("only expected a single closed connection")
					}
					closedConn = conn
				}
			}
			Expect(closedConn).ToNot(BeNil()) // there should be exactly one closed connection
			_, err = closedConn.AcceptStream(context.Background())
			var appErr *quic.ApplicationError
			Expect(errors.As(err, &appErr)).To(BeTrue())
			Expect(appErr.ErrorCode).To(Equal(appErrCode))
		})

		It("closes handshaking connections when the server is closed", func() {
			laddr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			udpConn, err := net.ListenUDP("udp", laddr)
			Expect(err).ToNot(HaveOccurred())
			tr := quic.Transport{
				Conn: udpConn,
			}
			defer tr.Close()
			tlsConf := &tls.Config{}
			done := make(chan struct{})
			tlsConf.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				<-done
				return nil, errors.New("closed")
			}
			ln, err := tr.Listen(tlsConf, getQuicConfig(nil))
			Expect(err).ToNot(HaveOccurred())

			errChan := make(chan error, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			go func() {
				defer GinkgoRecover()
				_, err := quic.DialAddr(ctx, ln.Addr().String(), getTLSClientConfig(), getQuicConfig(nil))
				errChan <- err
			}()
			time.Sleep(scaleDuration(20 * time.Millisecond)) // wait a bit for the connection to be queued
			Expect(ln.Close()).To(Succeed())
			close(done)
			err = <-errChan
			var transportErr *quic.TransportError
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode).To(Equal(quic.ConnectionRefused))
		})
	})

	Context("limiting handshakes", func() {
		var conn *net.UDPConn

		BeforeEach(func() {
			addr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			conn, err = net.ListenUDP("udp", addr)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() { conn.Close() })

		It("sends a Retry when the number of handshakes reaches MaxUnvalidatedHandshakes", func() {
			const limit = 3
			tr := quic.Transport{
				Conn:                     conn,
				MaxUnvalidatedHandshakes: limit,
			}
			defer tr.Close()

			// Block all handshakes.
			handshakes := make(chan struct{})
			var tlsConf tls.Config
			tlsConf.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
				handshakes <- struct{}{}
				return getTLSConfig(), nil
			}
			ln, err := tr.Listen(&tlsConf, getQuicConfig(nil))
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()

			const additional = 2
			results := make([]struct{ retry, closed atomic.Bool }, limit+additional)
			// Dial the server from multiple clients. All handshakes will get blocked on the handshakes channel.
			// Since we're dialing limit+2 times, we expect limit handshakes to go through with a Retry, and
			// exactly 2 to experience a Retry.
			for i := 0; i < limit+additional; i++ {
				go func(index int) {
					defer GinkgoRecover()
					quicConf := getQuicConfig(&quic.Config{
						Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
							return &logging.ConnectionTracer{
								ReceivedRetry:    func(*logging.Header) { results[index].retry.Store(true) },
								ClosedConnection: func(error) { results[index].closed.Store(true) },
							}
						},
					})
					conn, err := quic.DialAddr(context.Background(), ln.Addr().String(), getTLSClientConfig(), quicConf)
					Expect(err).ToNot(HaveOccurred())
					conn.CloseWithError(0, "")
				}(i)
			}
			numRetries := func() (n int) {
				for i := 0; i < limit+additional; i++ {
					if results[i].retry.Load() {
						n++
					}
				}
				return
			}
			numClosed := func() (n int) {
				for i := 0; i < limit+2; i++ {
					if results[i].closed.Load() {
						n++
					}
				}
				return
			}
			Eventually(numRetries).Should(Equal(additional))
			// allow the handshakes to complete
			for i := 0; i < limit+additional; i++ {
				Eventually(handshakes).Should(Receive())
			}
			Eventually(numClosed).Should(Equal(limit + additional))
			Expect(numRetries()).To(Equal(additional)) // just to be on the safe side
		})

		It("rejects connections when the number of handshakes reaches MaxHandshakes", func() {
			const limit = 3
			tr := quic.Transport{
				Conn:          conn,
				MaxHandshakes: limit,
			}
			defer tr.Close()

			// Block all handshakes.
			handshakes := make(chan struct{})
			var tlsConf tls.Config
			tlsConf.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
				handshakes <- struct{}{}
				return getTLSConfig(), nil
			}
			ln, err := tr.Listen(&tlsConf, getQuicConfig(nil))
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()

			const additional = 2
			// Dial the server from multiple clients. All handshakes will get blocked on the handshakes channel.
			// Since we're dialing limit+2 times, we expect limit handshakes to go through with a Retry, and
			// exactly 2 to experience a Retry.
			var numSuccessful, numFailed atomic.Int32
			for i := 0; i < limit+additional; i++ {
				go func() {
					defer GinkgoRecover()
					quicConf := getQuicConfig(&quic.Config{
						Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
							return &logging.ConnectionTracer{
								ReceivedRetry: func(*logging.Header) { Fail("didn't expect any Retry") },
							}
						},
					})
					conn, err := quic.DialAddr(context.Background(), ln.Addr().String(), getTLSClientConfig(), quicConf)
					if err != nil {
						var transportErr *quic.TransportError
						if !errors.As(err, &transportErr) || transportErr.ErrorCode != qerr.ConnectionRefused {
							Fail(fmt.Sprintf("expected CONNECTION_REFUSED error, got %v", err))
						}
						numFailed.Add(1)
						return
					}
					numSuccessful.Add(1)
					conn.CloseWithError(0, "")
				}()
			}
			Eventually(func() int { return int(numFailed.Load()) }).Should(Equal(additional))
			// allow the handshakes to complete
			for i := 0; i < limit; i++ {
				Eventually(handshakes).Should(Receive())
			}
			Eventually(func() int { return int(numSuccessful.Load()) }).Should(Equal(limit))

			// make sure that the server is reachable again after these handshakes have completed
			go func() { <-handshakes }() // allow this handshake to complete immediately
			conn, err := quic.DialAddr(context.Background(), ln.Addr().String(), getTLSClientConfig(), getQuicConfig(nil))
			Expect(err).ToNot(HaveOccurred())
			conn.CloseWithError(0, "")
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
			const rtt = 10 * time.Millisecond

			// The validity period of the retry token is the handshake timeout,
			// which is twice the handshake idle timeout.
			// By setting the handshake timeout shorter than the RTT, the token will have expired by the time
			// it reaches the server.
			serverConfig.HandshakeIdleTimeout = rtt / 5

			laddr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			udpConn, err := net.ListenUDP("udp", laddr)
			Expect(err).ToNot(HaveOccurred())
			defer udpConn.Close()
			tr := &quic.Transport{
				Conn:                     udpConn,
				MaxUnvalidatedHandshakes: -1,
			}
			defer tr.Close()
			server, err := tr.Listen(getTLSConfig(), serverConfig)
			Expect(err).ToNot(HaveOccurred())
			defer server.Close()

			serverPort := server.Addr().(*net.UDPAddr).Port
			proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
				RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
				DelayPacket: func(quicproxy.Direction, []byte) time.Duration {
					return rtt / 2
				},
			})
			Expect(err).ToNot(HaveOccurred())
			defer proxy.Close()

			_, err = quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", proxy.LocalPort()),
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
