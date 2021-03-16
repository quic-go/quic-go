package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"time"

	mocklogging "github.com/lucas-clemente/quic-go/internal/mocks/logging"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/logging"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client", func() {
	var (
		cl              *client
		packetConn      *MockPacketConn
		addr            net.Addr
		connID          protocol.ConnectionID
		mockMultiplexer *MockMultiplexer
		origMultiplexer multiplexer
		tlsConf         *tls.Config
		tracer          *mocklogging.MockConnectionTracer
		config          *Config

		originalClientSessConstructor func(
			conn sendConn,
			runner sessionRunner,
			destConnID protocol.ConnectionID,
			srcConnID protocol.ConnectionID,
			conf *Config,
			tlsConf *tls.Config,
			initialPacketNumber protocol.PacketNumber,
			enable0RTT bool,
			hasNegotiatedVersion bool,
			tracer logging.ConnectionTracer,
			logger utils.Logger,
			v protocol.VersionNumber,
		) quicSession
	)

	BeforeEach(func() {
		tlsConf = &tls.Config{NextProtos: []string{"proto1"}}
		connID = protocol.ConnectionID{0, 0, 0, 0, 0, 0, 0x13, 0x37}
		originalClientSessConstructor = newClientSession
		tracer = mocklogging.NewMockConnectionTracer(mockCtrl)
		tr := mocklogging.NewMockTracer(mockCtrl)
		tr.EXPECT().TracerForConnection(protocol.PerspectiveClient, gomock.Any()).Return(tracer).MaxTimes(1)
		config = &Config{Tracer: tr, Versions: []protocol.VersionNumber{protocol.VersionTLS}}
		Eventually(areSessionsRunning).Should(BeFalse())
		// sess = NewMockQuicSession(mockCtrl)
		addr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
		packetConn = NewMockPacketConn(mockCtrl)
		packetConn.EXPECT().LocalAddr().Return(&net.UDPAddr{}).AnyTimes()
		cl = &client{
			srcConnID:  connID,
			destConnID: connID,
			version:    protocol.VersionTLS,
			conn:       newSendPconn(packetConn, addr),
			tracer:     tracer,
			logger:     utils.DefaultLogger,
		}
		getMultiplexer() // make the sync.Once execute
		// replace the clientMuxer. getClientMultiplexer will now return the MockMultiplexer
		mockMultiplexer = NewMockMultiplexer(mockCtrl)
		origMultiplexer = connMuxer
		connMuxer = mockMultiplexer
	})

	AfterEach(func() {
		connMuxer = origMultiplexer
		newClientSession = originalClientSessConstructor
	})

	AfterEach(func() {
		if s, ok := cl.session.(*session); ok {
			s.shutdown()
		}
		Eventually(areSessionsRunning).Should(BeFalse())
	})

	Context("Dialing", func() {
		var origGenerateConnectionID func(int) (protocol.ConnectionID, error)
		var origGenerateConnectionIDForInitial func() (protocol.ConnectionID, error)

		BeforeEach(func() {
			origGenerateConnectionID = generateConnectionID
			origGenerateConnectionIDForInitial = generateConnectionIDForInitial
			generateConnectionID = func(int) (protocol.ConnectionID, error) {
				return connID, nil
			}
			generateConnectionIDForInitial = func() (protocol.ConnectionID, error) {
				return connID, nil
			}
		})

		AfterEach(func() {
			generateConnectionID = origGenerateConnectionID
			generateConnectionIDForInitial = origGenerateConnectionIDForInitial
		})

		It("resolves the address", func() {
			if os.Getenv("APPVEYOR") == "True" {
				Skip("This test is flaky on AppVeyor.")
			}

			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			manager.EXPECT().Destroy()
			mockMultiplexer.EXPECT().AddConn(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(manager, nil)

			remoteAddrChan := make(chan string, 1)
			newClientSession = func(
				conn sendConn,
				_ sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ protocol.PacketNumber,
				_ bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicSession {
				remoteAddrChan <- conn.RemoteAddr().String()
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().run()
				sess.EXPECT().HandshakeComplete().Return(context.Background())
				return sess
			}
			_, err := DialAddr("localhost:17890", tlsConf, &Config{HandshakeIdleTimeout: time.Millisecond})
			Expect(err).ToNot(HaveOccurred())
			Eventually(remoteAddrChan).Should(Receive(Equal("127.0.0.1:17890")))
		})

		It("uses the tls.Config.ServerName as the hostname, if present", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			manager.EXPECT().Destroy()
			mockMultiplexer.EXPECT().AddConn(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(manager, nil)

			hostnameChan := make(chan string, 1)
			newClientSession = func(
				_ sendConn,
				_ sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				tlsConf *tls.Config,
				_ protocol.PacketNumber,
				_ bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicSession {
				hostnameChan <- tlsConf.ServerName
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().run()
				sess.EXPECT().HandshakeComplete().Return(context.Background())
				return sess
			}
			tlsConf.ServerName = "foobar"
			_, err := DialAddr("localhost:17890", tlsConf, nil)
			Expect(err).ToNot(HaveOccurred())
			Eventually(hostnameChan).Should(Receive(Equal("foobar")))
		})

		It("allows passing host without port as server name", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any(), gomock.Any(), gomock.Any()).Return(manager, nil)

			hostnameChan := make(chan string, 1)
			newClientSession = func(
				_ sendConn,
				_ sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				tlsConf *tls.Config,
				_ protocol.PacketNumber,
				_ bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicSession {
				hostnameChan <- tlsConf.ServerName
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().HandshakeComplete().Return(context.Background())
				sess.EXPECT().run()
				return sess
			}
			tracer.EXPECT().StartedConnection(packetConn.LocalAddr(), addr, protocol.VersionTLS, gomock.Any(), gomock.Any())
			_, err := Dial(
				packetConn,
				addr,
				"test.com",
				tlsConf,
				config,
			)
			Expect(err).ToNot(HaveOccurred())
			Eventually(hostnameChan).Should(Receive(Equal("test.com")))
		})

		It("returns after the handshake is complete", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any(), gomock.Any(), gomock.Any()).Return(manager, nil)

			run := make(chan struct{})
			newClientSession = func(
				_ sendConn,
				runner sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ protocol.PacketNumber,
				enable0RTT bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicSession {
				Expect(enable0RTT).To(BeFalse())
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().run().Do(func() { close(run) })
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				sess.EXPECT().HandshakeComplete().Return(ctx)
				return sess
			}
			tracer.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), protocol.VersionTLS, gomock.Any(), gomock.Any())
			s, err := Dial(
				packetConn,
				addr,
				"localhost:1337",
				tlsConf,
				config,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(s).ToNot(BeNil())
			Eventually(run).Should(BeClosed())
		})

		It("returns early sessions", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any(), gomock.Any(), gomock.Any()).Return(manager, nil)

			readyChan := make(chan struct{})
			done := make(chan struct{})
			newClientSession = func(
				_ sendConn,
				runner sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ protocol.PacketNumber,
				enable0RTT bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicSession {
				Expect(enable0RTT).To(BeTrue())
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().run().Do(func() { <-done })
				sess.EXPECT().HandshakeComplete().Return(context.Background())
				sess.EXPECT().earlySessionReady().Return(readyChan)
				return sess
			}

			go func() {
				defer GinkgoRecover()
				defer close(done)
				tracer.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), protocol.VersionTLS, gomock.Any(), gomock.Any())
				s, err := DialEarly(
					packetConn,
					addr,
					"localhost:1337",
					tlsConf,
					config,
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(s).ToNot(BeNil())
			}()
			Consistently(done).ShouldNot(BeClosed())
			close(readyChan)
			Eventually(done).Should(BeClosed())
		})

		It("returns an error that occurs while waiting for the handshake to complete", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any(), gomock.Any(), gomock.Any()).Return(manager, nil)

			testErr := errors.New("early handshake error")
			newClientSession = func(
				_ sendConn,
				_ sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ protocol.PacketNumber,
				_ bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicSession {
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().run().Return(testErr)
				sess.EXPECT().HandshakeComplete().Return(context.Background())
				return sess
			}
			tracer.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), protocol.VersionTLS, gomock.Any(), gomock.Any())
			_, err := Dial(
				packetConn,
				addr,
				"localhost:1337",
				tlsConf,
				config,
			)
			Expect(err).To(MatchError(testErr))
		})

		It("closes the session when the context is canceled", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any(), gomock.Any(), gomock.Any()).Return(manager, nil)

			sessionRunning := make(chan struct{})
			defer close(sessionRunning)
			sess := NewMockQuicSession(mockCtrl)
			sess.EXPECT().run().Do(func() {
				<-sessionRunning
			})
			sess.EXPECT().HandshakeComplete().Return(context.Background())
			newClientSession = func(
				_ sendConn,
				_ sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ protocol.PacketNumber,
				_ bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicSession {
				return sess
			}
			ctx, cancel := context.WithCancel(context.Background())
			dialed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				tracer.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), protocol.VersionTLS, gomock.Any(), gomock.Any())
				_, err := DialContext(
					ctx,
					packetConn,
					addr,
					"localhost:1337",
					tlsConf,
					config,
				)
				Expect(err).To(MatchError(context.Canceled))
				close(dialed)
			}()
			Consistently(dialed).ShouldNot(BeClosed())
			sess.EXPECT().shutdown()
			cancel()
			Eventually(dialed).Should(BeClosed())
		})

		It("closes the connection when it was created by DialAddr", func() {
			if os.Getenv("APPVEYOR") == "True" {
				Skip("This test is flaky on AppVeyor.")
			}

			manager := NewMockPacketHandlerManager(mockCtrl)
			mockMultiplexer.EXPECT().AddConn(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(manager, nil)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())

			var conn sendConn
			run := make(chan struct{})
			sessionCreated := make(chan struct{})
			sess := NewMockQuicSession(mockCtrl)
			newClientSession = func(
				connP sendConn,
				_ sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ protocol.PacketNumber,
				_ bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicSession {
				conn = connP
				close(sessionCreated)
				return sess
			}
			sess.EXPECT().run().Do(func() {
				<-run
			})
			sess.EXPECT().HandshakeComplete().Return(context.Background())

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := DialAddr("localhost:1337", tlsConf, nil)
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()

			Eventually(sessionCreated).Should(BeClosed())

			// check that the connection is not closed
			Expect(conn.Write([]byte("foobar"))).To(Succeed())

			manager.EXPECT().Destroy()
			close(run)
			time.Sleep(50 * time.Millisecond)

			Eventually(done).Should(BeClosed())
		})

		Context("quic.Config", func() {
			It("setups with the right values", func() {
				tokenStore := NewLRUTokenStore(10, 4)
				config := &Config{
					HandshakeIdleTimeout:  1337 * time.Minute,
					MaxIdleTimeout:        42 * time.Hour,
					MaxIncomingStreams:    1234,
					MaxIncomingUniStreams: 4321,
					ConnectionIDLength:    13,
					StatelessResetKey:     []byte("foobar"),
					TokenStore:            tokenStore,
					EnableDatagrams:       true,
				}
				c := populateClientConfig(config, false)
				Expect(c.HandshakeIdleTimeout).To(Equal(1337 * time.Minute))
				Expect(c.MaxIdleTimeout).To(Equal(42 * time.Hour))
				Expect(c.MaxIncomingStreams).To(BeEquivalentTo(1234))
				Expect(c.MaxIncomingUniStreams).To(BeEquivalentTo(4321))
				Expect(c.ConnectionIDLength).To(Equal(13))
				Expect(c.StatelessResetKey).To(Equal([]byte("foobar")))
				Expect(c.TokenStore).To(Equal(tokenStore))
				Expect(c.EnableDatagrams).To(BeTrue())
			})

			It("errors when the Config contains an invalid version", func() {
				manager := NewMockPacketHandlerManager(mockCtrl)
				mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any(), gomock.Any(), gomock.Any()).Return(manager, nil)

				version := protocol.VersionNumber(0x1234)
				_, err := Dial(packetConn, nil, "localhost:1234", tlsConf, &Config{Versions: []protocol.VersionNumber{version}})
				Expect(err).To(MatchError("0x1234 is not a valid QUIC version"))
			})

			It("disables bidirectional streams", func() {
				config := &Config{
					MaxIncomingStreams:    -1,
					MaxIncomingUniStreams: 4321,
				}
				c := populateClientConfig(config, false)
				Expect(c.MaxIncomingStreams).To(BeZero())
				Expect(c.MaxIncomingUniStreams).To(BeEquivalentTo(4321))
			})

			It("disables unidirectional streams", func() {
				config := &Config{
					MaxIncomingStreams:    1234,
					MaxIncomingUniStreams: -1,
				}
				c := populateClientConfig(config, false)
				Expect(c.MaxIncomingStreams).To(BeEquivalentTo(1234))
				Expect(c.MaxIncomingUniStreams).To(BeZero())
			})

			It("uses 0-byte connection IDs when dialing an address", func() {
				c := populateClientConfig(&Config{}, true)
				Expect(c.ConnectionIDLength).To(BeZero())
			})

			It("fills in default values if options are not set in the Config", func() {
				c := populateClientConfig(&Config{}, false)
				Expect(c.Versions).To(Equal(protocol.SupportedVersions))
				Expect(c.HandshakeIdleTimeout).To(Equal(protocol.DefaultHandshakeIdleTimeout))
				Expect(c.MaxIdleTimeout).To(Equal(protocol.DefaultIdleTimeout))
			})
		})

		It("creates new sessions with the right parameters", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(connID, gomock.Any())
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any(), gomock.Any(), gomock.Any()).Return(manager, nil)

			config := &Config{Versions: []protocol.VersionNumber{protocol.VersionTLS}}
			c := make(chan struct{})
			var cconn sendConn
			var version protocol.VersionNumber
			var conf *Config
			newClientSession = func(
				connP sendConn,
				_ sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				configP *Config,
				_ *tls.Config,
				_ protocol.PacketNumber,
				_ bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				versionP protocol.VersionNumber,
			) quicSession {
				cconn = connP
				version = versionP
				conf = configP
				close(c)
				// TODO: check connection IDs?
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().run()
				sess.EXPECT().HandshakeComplete().Return(context.Background())
				return sess
			}
			_, err := Dial(packetConn, addr, "localhost:1337", tlsConf, config)
			Expect(err).ToNot(HaveOccurred())
			Eventually(c).Should(BeClosed())
			Expect(cconn.(*spconn).PacketConn).To(Equal(packetConn))
			Expect(version).To(Equal(config.Versions[0]))
			Expect(conf.Versions).To(Equal(config.Versions))
		})

		It("creates a new session after version negotiation", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(connID, gomock.Any()).Times(2)
			manager.EXPECT().Destroy()
			mockMultiplexer.EXPECT().AddConn(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(manager, nil)

			initialVersion := cl.version

			var counter int
			newClientSession = func(
				_ sendConn,
				_ sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				configP *Config,
				_ *tls.Config,
				pn protocol.PacketNumber,
				_ bool,
				hasNegotiatedVersion bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				versionP protocol.VersionNumber,
			) quicSession {
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().HandshakeComplete().Return(context.Background())
				if counter == 0 {
					Expect(pn).To(BeZero())
					Expect(hasNegotiatedVersion).To(BeFalse())
					sess.EXPECT().run().Return(&errCloseForRecreating{
						nextPacketNumber: 109,
						nextVersion:      789,
					})
				} else {
					Expect(pn).To(Equal(protocol.PacketNumber(109)))
					Expect(hasNegotiatedVersion).To(BeTrue())
					sess.EXPECT().run()
				}
				counter++
				return sess
			}

			gomock.InOrder(
				tracer.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), initialVersion, gomock.Any(), gomock.Any()),
				tracer.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), protocol.VersionNumber(789), gomock.Any(), gomock.Any()),
			)
			_, err := DialAddr("localhost:7890", tlsConf, config)
			Expect(err).ToNot(HaveOccurred())
			Expect(counter).To(Equal(2))
		})
	})
})
