package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client", func() {
	var (
		cl              *client
		packetConn      *mockPacketConn
		addr            net.Addr
		connID          protocol.ConnectionID
		mockMultiplexer *MockMultiplexer
		origMultiplexer multiplexer

		originalClientSessConstructor func(
			conn connection,
			runner sessionRunner,
			token []byte,
			origDestConnID protocol.ConnectionID,
			destConnID protocol.ConnectionID,
			srcConnID protocol.ConnectionID,
			conf *Config,
			tlsConf *tls.Config,
			params *handshake.TransportParameters,
			initialVersion protocol.VersionNumber,
			logger utils.Logger,
			v protocol.VersionNumber,
		) (quicSession, error)
	)

	// generate a packet sent by the server that accepts the QUIC version suggested by the client
	acceptClientVersionPacket := func(connID protocol.ConnectionID) []byte {
		b := &bytes.Buffer{}
		err := (&wire.Header{
			DestConnectionID: connID,
			PacketNumber:     1,
			PacketNumberLen:  1,
		}).Write(b, protocol.PerspectiveServer, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		return b.Bytes()
	}

	composeVersionNegotiationPacket := func(connID protocol.ConnectionID, versions []protocol.VersionNumber) *receivedPacket {
		return &receivedPacket{
			rcvTime: time.Now(),
			header: &wire.Header{
				IsVersionNegotiation: true,
				DestConnectionID:     connID,
				SupportedVersions:    versions,
			},
		}
	}

	BeforeEach(func() {
		connID = protocol.ConnectionID{0, 0, 0, 0, 0, 0, 0x13, 0x37}
		originalClientSessConstructor = newClientSession
		Eventually(areSessionsRunning).Should(BeFalse())
		// sess = NewMockQuicSession(mockCtrl)
		addr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
		packetConn = newMockPacketConn()
		packetConn.addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
		packetConn.dataReadFrom = addr
		cl = &client{
			srcConnID:  connID,
			destConnID: connID,
			version:    protocol.SupportedVersions[0],
			conn:       &conn{pconn: packetConn, currentAddr: addr},
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
			s.Close()
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
			mockMultiplexer.EXPECT().AddConn(gomock.Any(), gomock.Any()).Return(manager, nil)

			remoteAddrChan := make(chan string, 1)
			newClientSession = func(
				conn connection,
				_ sessionRunner,
				_ []byte, // token
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ protocol.VersionNumber,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				remoteAddrChan <- conn.RemoteAddr().String()
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().run()
				return sess, nil
			}
			_, err := DialAddr("localhost:17890", nil, &Config{HandshakeTimeout: time.Millisecond})
			Expect(err).ToNot(HaveOccurred())
			Eventually(remoteAddrChan).Should(Receive(Equal("127.0.0.1:17890")))
		})

		It("uses the tls.Config.ServerName as the hostname, if present", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			mockMultiplexer.EXPECT().AddConn(gomock.Any(), gomock.Any()).Return(manager, nil)

			hostnameChan := make(chan string, 1)
			newClientSession = func(
				_ connection,
				_ sessionRunner,
				_ []byte, // token
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				tlsConf *tls.Config,
				_ *handshake.TransportParameters,
				_ protocol.VersionNumber,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				hostnameChan <- tlsConf.ServerName
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().run()
				return sess, nil
			}
			_, err := DialAddr("localhost:17890", &tls.Config{ServerName: "foobar"}, nil)
			Expect(err).ToNot(HaveOccurred())
			Eventually(hostnameChan).Should(Receive(Equal("foobar")))
		})

		It("returns after the handshake is complete", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any()).Return(manager, nil)

			run := make(chan struct{})
			newClientSession = func(
				_ connection,
				runner sessionRunner,
				_ []byte, // token
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ protocol.VersionNumber,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().run().Do(func() { close(run) })
				runner.onHandshakeComplete(sess)
				return sess, nil
			}
			s, err := Dial(
				packetConn,
				addr,
				"localhost:1337",
				nil,
				&Config{},
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(s).ToNot(BeNil())
			Eventually(run).Should(BeClosed())
		})

		It("returns an error that occurs while waiting for the connection to become secure", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any()).Return(manager, nil)

			testErr := errors.New("early handshake error")
			newClientSession = func(
				_ connection,
				_ sessionRunner,
				_ []byte, // token
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ protocol.VersionNumber,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().run().Return(testErr)
				return sess, nil
			}
			packetConn.dataToRead <- acceptClientVersionPacket(cl.srcConnID)
			_, err := Dial(
				packetConn,
				addr,
				"localhost:1337",
				nil,
				&Config{},
			)
			Expect(err).To(MatchError(testErr))
		})

		It("closes the session when the context is canceled", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any()).Return(manager, nil)

			sessionRunning := make(chan struct{})
			defer close(sessionRunning)
			sess := NewMockQuicSession(mockCtrl)
			sess.EXPECT().run().Do(func() {
				<-sessionRunning
			})
			newClientSession = func(
				_ connection,
				_ sessionRunner,
				_ []byte, // token
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ protocol.VersionNumber,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				return sess, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			dialed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := DialContext(
					ctx,
					packetConn,
					addr,
					"localhost:1337",
					nil,
					&Config{},
				)
				Expect(err).To(MatchError(context.Canceled))
				close(dialed)
			}()
			Consistently(dialed).ShouldNot(BeClosed())
			sess.EXPECT().Close()
			cancel()
			Eventually(dialed).Should(BeClosed())
		})

		It("removes closed sessions from the multiplexer", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(connID, gomock.Any())
			manager.EXPECT().Retire(connID)
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any()).Return(manager, nil)

			var runner sessionRunner
			sess := NewMockQuicSession(mockCtrl)
			newClientSession = func(
				_ connection,
				runnerP sessionRunner,
				_ []byte, // token
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ protocol.VersionNumber,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				runner = runnerP
				return sess, nil
			}
			sess.EXPECT().run().Do(func() {
				runner.retireConnectionID(connID)
			})

			_, err := DialContext(
				context.Background(),
				packetConn,
				addr,
				"localhost:1337",
				nil,
				&Config{},
			)
			Expect(err).ToNot(HaveOccurred())
		})

		It("closes the connection when it was created by DialAddr", func() {
			if os.Getenv("APPVEYOR") == "True" {
				Skip("This test is flaky on AppVeyor.")
			}

			manager := NewMockPacketHandlerManager(mockCtrl)
			mockMultiplexer.EXPECT().AddConn(gomock.Any(), gomock.Any()).Return(manager, nil)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())

			var conn connection
			run := make(chan struct{})
			sessionCreated := make(chan struct{})
			sess := NewMockQuicSession(mockCtrl)
			newClientSession = func(
				connP connection,
				_ sessionRunner,
				_ []byte, // token
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ protocol.VersionNumber,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				conn = connP
				close(sessionCreated)
				return sess, nil
			}
			sess.EXPECT().run().Do(func() {
				<-run
			})

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := DialAddr("localhost:1337", nil, nil)
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()

			Eventually(sessionCreated).Should(BeClosed())

			// check that the connection is not closed
			Expect(conn.Write([]byte("foobar"))).To(Succeed())

			close(run)
			time.Sleep(50 * time.Millisecond)
			// check that the connection is closed
			err := conn.Write([]byte("foobar"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("use of closed network connection"))

			Eventually(done).Should(BeClosed())
		})

		Context("quic.Config", func() {
			It("setups with the right values", func() {
				config := &Config{
					HandshakeTimeout:      1337 * time.Minute,
					IdleTimeout:           42 * time.Hour,
					MaxIncomingStreams:    1234,
					MaxIncomingUniStreams: 4321,
					ConnectionIDLength:    13,
				}
				c := populateClientConfig(config, false)
				Expect(c.HandshakeTimeout).To(Equal(1337 * time.Minute))
				Expect(c.IdleTimeout).To(Equal(42 * time.Hour))
				Expect(c.MaxIncomingStreams).To(Equal(1234))
				Expect(c.MaxIncomingUniStreams).To(Equal(4321))
				Expect(c.ConnectionIDLength).To(Equal(13))
			})

			It("errors when the Config contains an invalid version", func() {
				manager := NewMockPacketHandlerManager(mockCtrl)
				mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any()).Return(manager, nil)

				version := protocol.VersionNumber(0x1234)
				_, err := Dial(packetConn, nil, "localhost:1234", &tls.Config{}, &Config{Versions: []protocol.VersionNumber{version}})
				Expect(err).To(MatchError("0x1234 is not a valid QUIC version"))
			})

			It("disables bidirectional streams", func() {
				config := &Config{
					MaxIncomingStreams:    -1,
					MaxIncomingUniStreams: 4321,
				}
				c := populateClientConfig(config, false)
				Expect(c.MaxIncomingStreams).To(BeZero())
				Expect(c.MaxIncomingUniStreams).To(Equal(4321))
			})

			It("disables unidirectional streams", func() {
				config := &Config{
					MaxIncomingStreams:    1234,
					MaxIncomingUniStreams: -1,
				}
				c := populateClientConfig(config, false)
				Expect(c.MaxIncomingStreams).To(Equal(1234))
				Expect(c.MaxIncomingUniStreams).To(BeZero())
			})

			It("uses 0-byte connection IDs when dialing an address", func() {
				config := &Config{}
				c := populateClientConfig(config, true)
				Expect(c.ConnectionIDLength).To(BeZero())
			})

			It("fills in default values if options are not set in the Config", func() {
				c := populateClientConfig(&Config{}, false)
				Expect(c.Versions).To(Equal(protocol.SupportedVersions))
				Expect(c.HandshakeTimeout).To(Equal(protocol.DefaultHandshakeTimeout))
				Expect(c.IdleTimeout).To(Equal(protocol.DefaultIdleTimeout))
			})
		})

		It("creates new TLS sessions with the right parameters", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(connID, gomock.Any())
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any()).Return(manager, nil)

			config := &Config{Versions: []protocol.VersionNumber{protocol.VersionTLS}}
			c := make(chan struct{})
			var cconn connection
			var version protocol.VersionNumber
			var conf *Config
			newClientSession = func(
				connP connection,
				_ sessionRunner,
				tokenP []byte,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				configP *Config,
				_ *tls.Config,
				params *handshake.TransportParameters,
				_ protocol.VersionNumber, /* initial version */
				_ utils.Logger,
				versionP protocol.VersionNumber,
			) (quicSession, error) {
				cconn = connP
				version = versionP
				conf = configP
				close(c)
				// TODO: check connection IDs?
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().run()
				return sess, nil
			}
			_, err := Dial(packetConn, addr, "localhost:1337", nil, config)
			Expect(err).ToNot(HaveOccurred())
			Eventually(c).Should(BeClosed())
			Expect(cconn.(*conn).pconn).To(Equal(packetConn))
			Expect(version).To(Equal(config.Versions[0]))
			Expect(conf.Versions).To(Equal(config.Versions))
		})

		It("creates a new session when the server performs a retry", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any()).Do(func(id protocol.ConnectionID, handler packetHandler) {
				go handler.handlePacket(&receivedPacket{
					header: &wire.Header{
						IsLongHeader:         true,
						Type:                 protocol.PacketTypeRetry,
						Token:                []byte("foobar"),
						DestConnectionID:     id,
						OrigDestConnectionID: connID,
					},
				})
			})
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any()).Return(manager, nil)

			config := &Config{Versions: []protocol.VersionNumber{protocol.VersionTLS}}
			cl.config = config
			run1 := make(chan error)
			sess1 := NewMockQuicSession(mockCtrl)
			sess1.EXPECT().run().DoAndReturn(func() error {
				return <-run1
			})
			sess1.EXPECT().destroy(errCloseSessionForRetry).Do(func(e error) {
				run1 <- e
			})
			sess2 := NewMockQuicSession(mockCtrl)
			sess2.EXPECT().run()
			sessions := make(chan quicSession, 2)
			sessions <- sess1
			sessions <- sess2
			newClientSession = func(
				conn connection,
				_ sessionRunner,
				_ []byte, // token
				origDestConnID protocol.ConnectionID,
				destConnID protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ protocol.VersionNumber,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				switch len(sessions) {
				case 2: // for the first session
					Expect(origDestConnID).To(BeNil())
					Expect(destConnID).ToNot(BeNil())
				case 1: // for the second session
					Expect(origDestConnID).To(Equal(connID))
					Expect(destConnID).ToNot(Equal(connID))
				}
				return <-sessions, nil
			}
			_, err := Dial(packetConn, addr, "localhost:1337", nil, config)
			Expect(err).ToNot(HaveOccurred())
			Expect(sessions).To(BeEmpty())
		})

		It("only accepts a single retry", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any()).Do(func(id protocol.ConnectionID, handler packetHandler) {
				go handler.handlePacket(&receivedPacket{
					header: &wire.Header{
						IsLongHeader:         true,
						Type:                 protocol.PacketTypeRetry,
						Token:                []byte("foobar"),
						SrcConnectionID:      protocol.ConnectionID{1, 2, 3, 4},
						DestConnectionID:     id,
						OrigDestConnectionID: connID,
						Version:              protocol.VersionTLS,
					},
				})
			}).AnyTimes()
			manager.EXPECT().Add(gomock.Any(), gomock.Any()).AnyTimes()
			mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any()).Return(manager, nil)

			config := &Config{Versions: []protocol.VersionNumber{protocol.VersionTLS}}
			cl.config = config

			sessions := make(chan quicSession, 2)
			run := make(chan error)
			sess := NewMockQuicSession(mockCtrl)
			sess.EXPECT().run().DoAndReturn(func() error {
				defer GinkgoRecover()
				var err error
				Eventually(run).Should(Receive(&err))
				return err
			})
			sess.EXPECT().destroy(gomock.Any()).Do(func(e error) {
				run <- e
			})
			sessions <- sess
			doneErr := errors.New("nothing to do")
			sess = NewMockQuicSession(mockCtrl)
			sess.EXPECT().run().Return(doneErr)
			sessions <- sess

			newClientSession = func(
				conn connection,
				_ sessionRunner,
				_ []byte, // token
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ protocol.VersionNumber,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				return <-sessions, nil
			}
			_, err := Dial(packetConn, addr, "localhost:1337", nil, config)
			Expect(err).To(MatchError(doneErr))
			Expect(sessions).To(BeEmpty())
		})

		Context("version negotiation", func() {
			var origSupportedVersions []protocol.VersionNumber

			BeforeEach(func() {
				origSupportedVersions = protocol.SupportedVersions
				protocol.SupportedVersions = append(protocol.SupportedVersions, []protocol.VersionNumber{77, 78}...)
			})

			AfterEach(func() {
				protocol.SupportedVersions = origSupportedVersions
			})

			It("returns an error that occurs during version negotiation", func() {
				manager := NewMockPacketHandlerManager(mockCtrl)
				manager.EXPECT().Add(connID, gomock.Any())
				mockMultiplexer.EXPECT().AddConn(packetConn, gomock.Any()).Return(manager, nil)

				testErr := errors.New("early handshake error")
				newClientSession = func(
					conn connection,
					_ sessionRunner,
					_ []byte, // token
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TransportParameters,
					_ protocol.VersionNumber,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) (quicSession, error) {
					Expect(conn.Write([]byte("0 fake CHLO"))).To(Succeed())
					sess := NewMockQuicSession(mockCtrl)
					sess.EXPECT().run().Return(testErr)
					return sess, nil
				}
				_, err := Dial(
					packetConn,
					addr,
					"localhost:1337",
					nil,
					&Config{},
				)
				Expect(err).To(MatchError(testErr))
			})

			It("recognizes that a packet without VersionFlag means that the server accepted the suggested version", func() {
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().handlePacket(gomock.Any())
				cl.session = sess
				cl.config = &Config{}
				ph := &wire.Header{
					PacketNumber:     1,
					PacketNumberLen:  protocol.PacketNumberLen2,
					DestConnectionID: connID,
					SrcConnectionID:  connID,
				}
				err := cl.handlePacketImpl(&receivedPacket{header: ph})
				Expect(err).ToNot(HaveOccurred())
				Expect(cl.versionNegotiated).To(BeTrue())
			})

			It("errors if no matching version is found", func() {
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().destroy(qerr.InvalidVersion)
				cl.session = sess
				cl.config = &Config{Versions: protocol.SupportedVersions}
				cl.handlePacket(composeVersionNegotiationPacket(connID, []protocol.VersionNumber{1}))
			})

			It("errors if the version is supported by quic-go, but disabled by the quic.Config", func() {
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().destroy(qerr.InvalidVersion)
				cl.session = sess
				v := protocol.VersionNumber(1234)
				Expect(v).ToNot(Equal(cl.version))
				cl.config = &Config{Versions: protocol.SupportedVersions}
				cl.handlePacket(composeVersionNegotiationPacket(connID, []protocol.VersionNumber{v}))
			})

			It("changes to the version preferred by the quic.Config", func() {
				phm := NewMockPacketHandlerManager(mockCtrl)
				cl.packetHandlers = phm

				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().destroy(errCloseSessionForNewVersion)
				cl.session = sess
				versions := []protocol.VersionNumber{1234, 4321}
				cl.config = &Config{Versions: versions}
				cl.handlePacket(composeVersionNegotiationPacket(connID, versions))
				Expect(cl.version).To(Equal(protocol.VersionNumber(1234)))
			})

			It("drops version negotiation packets that contain the offered version", func() {
				cl.config = &Config{}
				ver := cl.version
				cl.handlePacket(composeVersionNegotiationPacket(connID, []protocol.VersionNumber{ver}))
				Expect(cl.version).To(Equal(ver))
			})
		})
	})

	It("tells its version", func() {
		Expect(cl.version).ToNot(BeZero())
		Expect(cl.GetVersion()).To(Equal(cl.version))
	})

	It("ignores packets with the wrong destination connection ID", func() {
		cl.session = NewMockQuicSession(mockCtrl) // don't EXPECT any handlePacket calls
		connID2 := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
		Expect(connID).ToNot(Equal(connID2))
		hdr := &wire.Header{
			DestConnectionID: connID2,
			SrcConnectionID:  connID,
			PacketNumber:     1,
			PacketNumberLen:  protocol.PacketNumberLen1,
		}
		err := cl.handlePacketImpl(&receivedPacket{
			remoteAddr: addr,
			header:     hdr,
		})
		Expect(err).To(MatchError(fmt.Sprintf("received a packet with an unexpected connection ID (0x0807060504030201, expected %s)", connID)))
	})
})
