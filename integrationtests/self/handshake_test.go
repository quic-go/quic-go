package self_test

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/israce"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type versioner interface {
	GetVersion() protocol.VersionNumber
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
		tlsServerConf = testdata.GetTLSConfig()
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
				if _, err := server.Accept(); err != nil {
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
				sess, err := quic.DialAddr(server.Addr().String(), &tls.Config{InsecureSkipVerify: true}, nil)
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
				sess, err := quic.DialAddr(server.Addr().String(), &tls.Config{InsecureSkipVerify: true}, conf)
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
				var (
					tlsConf      *tls.Config
					clientConfig *quic.Config
				)

				BeforeEach(func() {
					serverConfig.Versions = []protocol.VersionNumber{version}
					tlsConf = &tls.Config{RootCAs: testdata.GetRootCA()}
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
						tlsConf,
						clientConfig,
					)
					Expect(err).ToNot(HaveOccurred())
				})

				It("errors if the server name doesn't match", func() {
					_, err := quic.DialAddr(
						fmt.Sprintf("127.0.0.1:%d", server.Addr().(*net.UDPAddr).Port),
						tlsConf,
						clientConfig,
					)
					// TODO: check the error returned locally here
					Expect(err).To(HaveOccurred())
				})

				It("fails the handshake if the client fails to provide the requested client cert", func() {
					tlsServerConf.ClientAuth = tls.RequireAndVerifyClientCert
					sess, err := quic.DialAddr(
						fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
						tlsConf,
						clientConfig,
					)
					Expect(err).ToNot(HaveOccurred())
					// The error will occur after the client already finished the handshake.
					errChan := make(chan error)
					go func() {
						defer GinkgoRecover()
						_, err := sess.AcceptStream()
						errChan <- err
					}()
					Eventually(errChan).Should(Receive(MatchError("CRYPTO_ERROR: tls: bad certificate")))
				})

				It("uses the ServerName in the tls.Config", func() {
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
		var server quic.Listener

		dial := func() (quic.Session, error) {
			return quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				&tls.Config{RootCAs: testdata.GetRootCA()},
				nil,
			)
		}

		BeforeEach(func() {
			serverConfig.AcceptCookie = func(net.Addr, *quic.Cookie) bool { return true }
			var err error
			// start the server, but don't call Accept
			server, err = quic.ListenAddr("localhost:0", testdata.GetTLSConfig(), serverConfig)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			Expect(server.Close()).To(Succeed())
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
			_, err = server.Accept()
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

		It("rejects new connection attempts if connections don't get accepted", func() {
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
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.ServerBusy))
		})

	})
})
