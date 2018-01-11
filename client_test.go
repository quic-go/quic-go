package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client", func() {
	var (
		cl         *client
		config     *Config
		sess       *mockSession
		packetConn *mockPacketConn
		addr       net.Addr

		originalClientSessConstructor func(conn connection, hostname string, v protocol.VersionNumber, connectionID protocol.ConnectionID, tlsConf *tls.Config, config *Config, initialVersion protocol.VersionNumber, negotiatedVersions []protocol.VersionNumber) (packetHandler, error)
	)

	// generate a packet sent by the server that accepts the QUIC version suggested by the client
	acceptClientVersionPacket := func(connID protocol.ConnectionID) []byte {
		b := &bytes.Buffer{}
		err := (&wire.Header{
			ConnectionID:    connID,
			PacketNumber:    1,
			PacketNumberLen: 1,
		}).Write(b, protocol.PerspectiveServer, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		return b.Bytes()
	}

	BeforeEach(func() {
		originalClientSessConstructor = newClientSession
		Eventually(areSessionsRunning).Should(BeFalse())
		msess, _ := newMockSession(nil, 0, 0, nil, nil, nil)
		sess = msess.(*mockSession)
		addr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
		packetConn = newMockPacketConn()
		packetConn.addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
		packetConn.dataReadFrom = addr
		config = &Config{
			Versions: []protocol.VersionNumber{protocol.SupportedVersions[0], 77, 78},
		}
		cl = &client{
			config:       config,
			connectionID: 0x1337,
			session:      sess,
			version:      protocol.SupportedVersions[0],
			conn:         &conn{pconn: packetConn, currentAddr: addr},
			versionNegotiationChan: make(chan struct{}),
		}
	})

	AfterEach(func() {
		newClientSession = originalClientSessConstructor
	})

	AfterEach(func() {
		if s, ok := cl.session.(*session); ok {
			s.Close(nil)
		}
		Eventually(areSessionsRunning).Should(BeFalse())
	})

	Context("Dialing", func() {
		var origGenerateConnectionID func() (protocol.ConnectionID, error)

		BeforeEach(func() {
			newClientSession = func(
				conn connection,
				_ string,
				_ protocol.VersionNumber,
				_ protocol.ConnectionID,
				_ *tls.Config,
				_ *Config,
				_ protocol.VersionNumber,
				_ []protocol.VersionNumber,
			) (packetHandler, error) {
				Expect(conn.Write([]byte("0 fake CHLO"))).To(Succeed())
				return sess, nil
			}
			origGenerateConnectionID = generateConnectionID
			generateConnectionID = func() (protocol.ConnectionID, error) {
				return cl.connectionID, nil
			}
		})

		AfterEach(func() {
			generateConnectionID = origGenerateConnectionID
		})

		It("returns after the handshake is complete", func() {
			packetConn.dataToRead <- acceptClientVersionPacket(cl.connectionID)
			dialed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				s, err := Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
				Expect(err).ToNot(HaveOccurred())
				Expect(s).ToNot(BeNil())
				close(dialed)
			}()
			close(sess.handshakeChan)
			Eventually(dialed).Should(BeClosed())
		})

		It("resolves the address", func() {
			if os.Getenv("APPVEYOR") == "True" {
				Skip("This test is flaky on AppVeyor.")
			}
			closeErr := errors.New("peer doesn't reply")
			remoteAddrChan := make(chan string)
			newClientSession = func(
				conn connection,
				_ string,
				_ protocol.VersionNumber,
				_ protocol.ConnectionID,
				_ *tls.Config,
				_ *Config,
				_ protocol.VersionNumber,
				_ []protocol.VersionNumber,
			) (packetHandler, error) {
				remoteAddrChan <- conn.RemoteAddr().String()
				return sess, nil
			}
			dialed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := DialAddr("localhost:17890", nil, &Config{HandshakeTimeout: time.Millisecond})
				Expect(err).To(MatchError(closeErr))
				close(dialed)
			}()
			Eventually(remoteAddrChan).Should(Receive(Equal("127.0.0.1:17890")))
			sess.Close(closeErr)
			Eventually(dialed).Should(BeClosed())
		})

		It("uses the tls.Config.ServerName as the hostname, if present", func() {
			closeErr := errors.New("peer doesn't reply")
			hostnameChan := make(chan string)
			newClientSession = func(
				_ connection,
				h string,
				_ protocol.VersionNumber,
				_ protocol.ConnectionID,
				_ *tls.Config,
				_ *Config,
				_ protocol.VersionNumber,
				_ []protocol.VersionNumber,
			) (packetHandler, error) {
				hostnameChan <- h
				return sess, nil
			}
			dialed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := DialAddr("localhost:17890", &tls.Config{ServerName: "foobar"}, nil)
				Expect(err).To(MatchError(closeErr))
				close(dialed)
			}()
			Eventually(hostnameChan).Should(Receive(Equal("foobar")))
			sess.Close(closeErr)
			Eventually(dialed).Should(BeClosed())
		})

		It("returns an error that occurs during version negotiation", func() {
			testErr := errors.New("early handshake error")
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
				Expect(err).To(MatchError(testErr))
				close(done)
			}()
			sess.Close(testErr)
			Eventually(done).Should(BeClosed())
		})

		It("returns an error that occurs while waiting for the connection to become secure", func() {
			testErr := errors.New("early handshake error")
			packetConn.dataToRead <- acceptClientVersionPacket(cl.connectionID)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
				Expect(err).To(MatchError(testErr))
				close(done)
			}()
			sess.handshakeChan <- testErr
			Eventually(done).Should(BeClosed())
		})

		It("setups with the right values", func() {
			config := &Config{
				HandshakeTimeout:            1337 * time.Minute,
				IdleTimeout:                 42 * time.Hour,
				RequestConnectionIDOmission: true,
			}
			c := populateClientConfig(config)
			Expect(c.HandshakeTimeout).To(Equal(1337 * time.Minute))
			Expect(c.IdleTimeout).To(Equal(42 * time.Hour))
			Expect(c.RequestConnectionIDOmission).To(BeTrue())
		})

		It("fills in default values if options are not set in the Config", func() {
			c := populateClientConfig(&Config{})
			Expect(c.Versions).To(Equal(protocol.SupportedVersions))
			Expect(c.HandshakeTimeout).To(Equal(protocol.DefaultHandshakeTimeout))
			Expect(c.IdleTimeout).To(Equal(protocol.DefaultIdleTimeout))
			Expect(c.RequestConnectionIDOmission).To(BeFalse())
		})

		It("errors when receiving an error from the connection", func() {
			testErr := errors.New("connection error")
			packetConn.readErr = testErr
			_, err := Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
			Expect(err).To(MatchError(testErr))
		})

		It("errors if it can't create a session", func() {
			testErr := errors.New("error creating session")
			newClientSession = func(
				_ connection,
				_ string,
				_ protocol.VersionNumber,
				_ protocol.ConnectionID,
				_ *tls.Config,
				_ *Config,
				_ protocol.VersionNumber,
				_ []protocol.VersionNumber,
			) (packetHandler, error) {
				return nil, testErr
			}
			_, err := Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
			Expect(err).To(MatchError(testErr))
		})

		Context("version negotiation", func() {
			It("recognizes that a packet without VersionFlag means that the server accepted the suggested version", func() {
				ph := wire.Header{
					PacketNumber:    1,
					PacketNumberLen: protocol.PacketNumberLen2,
					ConnectionID:    0x1337,
				}
				b := &bytes.Buffer{}
				err := ph.Write(b, protocol.PerspectiveServer, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				cl.handlePacket(nil, b.Bytes())
				Expect(cl.versionNegotiated).To(BeTrue())
				Expect(cl.versionNegotiationChan).To(BeClosed())
			})

			It("changes the version after receiving a version negotiation packet", func() {
				var initialVersion protocol.VersionNumber
				var negotiatedVersions []protocol.VersionNumber
				newVersion := protocol.VersionNumber(77)
				Expect(newVersion).ToNot(Equal(cl.version))
				Expect(config.Versions).To(ContainElement(newVersion))
				sessionChan := make(chan *mockSession)
				handshakeChan := make(chan error)
				newClientSession = func(
					_ connection,
					_ string,
					_ protocol.VersionNumber,
					connectionID protocol.ConnectionID,
					_ *tls.Config,
					_ *Config,
					initialVersionP protocol.VersionNumber,
					negotiatedVersionsP []protocol.VersionNumber,
				) (packetHandler, error) {
					initialVersion = initialVersionP
					negotiatedVersions = negotiatedVersionsP

					sess := &mockSession{
						connectionID:  connectionID,
						stopRunLoop:   make(chan struct{}),
						handshakeChan: handshakeChan,
					}
					sessionChan <- sess
					return sess, nil
				}

				established := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					err := cl.dial()
					Expect(err).ToNot(HaveOccurred())
					close(established)
				}()
				go cl.listen()

				actualInitialVersion := cl.version
				var firstSession, secondSession *mockSession
				Eventually(sessionChan).Should(Receive(&firstSession))
				packetConn.dataToRead <- wire.ComposeGQUICVersionNegotiation(
					cl.connectionID,
					[]protocol.VersionNumber{newVersion},
				)
				// it didn't pass the version negoation packet to the old session (since it has no payload)
				Eventually(func() bool { return firstSession.closed }).Should(BeTrue())
				Expect(firstSession.closeReason).To(Equal(errCloseSessionForNewVersion))
				Expect(firstSession.packetCount).To(BeZero())
				Eventually(sessionChan).Should(Receive(&secondSession))
				// make the server accept the new version
				packetConn.dataToRead <- acceptClientVersionPacket(secondSession.connectionID)
				Consistently(func() bool { return secondSession.closed }).Should(BeFalse())
				Expect(cl.connectionID).ToNot(BeEquivalentTo(0x1337))
				Expect(negotiatedVersions).To(ContainElement(newVersion))
				Expect(initialVersion).To(Equal(actualInitialVersion))

				close(handshakeChan)
				Eventually(established).Should(BeClosed())
			})

			It("only accepts one version negotiation packet", func() {
				sessionCounter := uint32(0)
				newClientSession = func(
					_ connection,
					_ string,
					_ protocol.VersionNumber,
					connectionID protocol.ConnectionID,
					_ *tls.Config,
					_ *Config,
					_ protocol.VersionNumber,
					_ []protocol.VersionNumber,
				) (packetHandler, error) {
					atomic.AddUint32(&sessionCounter, 1)
					return &mockSession{
						connectionID: connectionID,
						stopRunLoop:  make(chan struct{}),
					}, nil
				}
				go cl.dial()
				Eventually(func() uint32 { return atomic.LoadUint32(&sessionCounter) }).Should(BeEquivalentTo(1))
				newVersion := protocol.VersionNumber(77)
				Expect(newVersion).ToNot(Equal(cl.version))
				Expect(config.Versions).To(ContainElement(newVersion))
				cl.handlePacket(nil, wire.ComposeGQUICVersionNegotiation(0x1337, []protocol.VersionNumber{newVersion}))
				Eventually(func() uint32 { return atomic.LoadUint32(&sessionCounter) }).Should(BeEquivalentTo(2))
				newVersion = protocol.VersionNumber(78)
				Expect(newVersion).ToNot(Equal(cl.version))
				Expect(config.Versions).To(ContainElement(newVersion))
				cl.handlePacket(nil, wire.ComposeGQUICVersionNegotiation(0x1337, []protocol.VersionNumber{newVersion}))
				Consistently(func() uint32 { return atomic.LoadUint32(&sessionCounter) }).Should(BeEquivalentTo(2))
			})

			It("errors if no matching version is found", func() {
				cl.handlePacket(nil, wire.ComposeGQUICVersionNegotiation(0x1337, []protocol.VersionNumber{1}))
				Expect(cl.session.(*mockSession).closed).To(BeTrue())
				Expect(cl.session.(*mockSession).closeReason).To(MatchError(qerr.InvalidVersion))
			})

			It("errors if the version is supported by quic-go, but disabled by the quic.Config", func() {
				v := protocol.VersionNumber(111)
				Expect(v).ToNot(Equal(cl.version))
				Expect(config.Versions).ToNot(ContainElement(v))
				cl.handlePacket(nil, wire.ComposeGQUICVersionNegotiation(0x1337, []protocol.VersionNumber{v}))
				Expect(cl.session.(*mockSession).closed).To(BeTrue())
				Expect(cl.session.(*mockSession).closeReason).To(MatchError(qerr.InvalidVersion))
			})

			It("changes to the version preferred by the quic.Config", func() {
				cl.handlePacket(nil, wire.ComposeGQUICVersionNegotiation(0x1337, []protocol.VersionNumber{config.Versions[2], config.Versions[1]}))
				Expect(cl.version).To(Equal(config.Versions[1]))
			})

			It("ignores delayed version negotiation packets", func() {
				// if the version was not yet negotiated, handlePacket would return a VersionNegotiationMismatch error, see above test
				cl.versionNegotiated = true
				Expect(sess.packetCount).To(BeZero())
				cl.handlePacket(nil, wire.ComposeGQUICVersionNegotiation(0x1337, []protocol.VersionNumber{1}))
				Expect(cl.versionNegotiated).To(BeTrue())
				Expect(sess.packetCount).To(BeZero())
			})

			It("drops version negotiation packets that contain the offered version", func() {
				ver := cl.version
				cl.handlePacket(nil, wire.ComposeGQUICVersionNegotiation(0x1337, []protocol.VersionNumber{ver}))
				Expect(cl.version).To(Equal(ver))
			})
		})
	})

	It("ignores packets with an invalid public header", func() {
		cl.handlePacket(addr, []byte("invalid packet"))
		Expect(sess.packetCount).To(BeZero())
		Expect(sess.closed).To(BeFalse())
	})

	It("ignores packets without connection id, if it didn't request connection id trunctation", func() {
		cl.config.RequestConnectionIDOmission = false
		buf := &bytes.Buffer{}
		(&wire.Header{
			OmitConnectionID: true,
			PacketNumber:     1,
			PacketNumberLen:  1,
		}).Write(buf, protocol.PerspectiveServer, protocol.VersionWhatever)
		cl.handlePacket(addr, buf.Bytes())
		Expect(sess.packetCount).To(BeZero())
		Expect(sess.closed).To(BeFalse())
	})

	It("ignores packets with the wrong connection ID", func() {
		buf := &bytes.Buffer{}
		(&wire.Header{
			ConnectionID:    cl.connectionID + 1,
			PacketNumber:    1,
			PacketNumberLen: 1,
		}).Write(buf, protocol.PerspectiveServer, protocol.VersionWhatever)
		cl.handlePacket(addr, buf.Bytes())
		Expect(sess.packetCount).To(BeZero())
		Expect(sess.closed).To(BeFalse())
	})

	It("creates new GQUIC sessions with the right parameters", func() {
		closeErr := errors.New("peer doesn't reply")
		c := make(chan struct{})
		var cconn connection
		var hostname string
		var version protocol.VersionNumber
		var conf *Config
		newClientSession = func(
			connP connection,
			hostnameP string,
			versionP protocol.VersionNumber,
			_ protocol.ConnectionID,
			_ *tls.Config,
			configP *Config,
			_ protocol.VersionNumber,
			_ []protocol.VersionNumber,
		) (packetHandler, error) {
			cconn = connP
			hostname = hostnameP
			version = versionP
			conf = configP
			close(c)
			return sess, nil
		}
		dialed := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, err := Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
			Expect(err).To(MatchError(closeErr))
			close(dialed)
		}()
		Eventually(c).Should(BeClosed())
		Expect(cconn.(*conn).pconn).To(Equal(packetConn))
		Expect(hostname).To(Equal("quic.clemente.io"))
		Expect(version).To(Equal(config.Versions[0]))
		Expect(conf.Versions).To(Equal(config.Versions))
		sess.Close(closeErr)
		Eventually(dialed).Should(BeClosed())
	})

	It("creates new TLS sessions with the right parameters", func() {
		config.Versions = []protocol.VersionNumber{protocol.VersionTLS}
		c := make(chan struct{})
		var cconn connection
		var hostname string
		var version protocol.VersionNumber
		var conf *Config
		newTLSClientSession = func(
			connP connection,
			hostnameP string,
			versionP protocol.VersionNumber,
			_ protocol.ConnectionID,
			configP *Config,
			tls handshake.MintTLS,
			paramsChan <-chan handshake.TransportParameters,
			_ protocol.PacketNumber,
		) (packetHandler, error) {
			cconn = connP
			hostname = hostnameP
			version = versionP
			conf = configP
			close(c)
			return sess, nil
		}
		dialed := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
			close(dialed)
		}()
		Eventually(c).Should(BeClosed())
		Expect(cconn.(*conn).pconn).To(Equal(packetConn))
		Expect(hostname).To(Equal("quic.clemente.io"))
		Expect(version).To(Equal(config.Versions[0]))
		Expect(conf.Versions).To(Equal(config.Versions))
		sess.Close(errors.New("peer doesn't reply"))
		Eventually(dialed).Should(BeClosed())
	})

	It("creates a new session when the server performs a retry", func() {
		config.Versions = []protocol.VersionNumber{protocol.VersionTLS}
		sessionChan := make(chan *mockSession)
		newTLSClientSession = func(
			connP connection,
			hostnameP string,
			versionP protocol.VersionNumber,
			_ protocol.ConnectionID,
			configP *Config,
			tls handshake.MintTLS,
			paramsChan <-chan handshake.TransportParameters,
			_ protocol.PacketNumber,
		) (packetHandler, error) {
			sess := &mockSession{
				stopRunLoop: make(chan struct{}),
			}
			sessionChan <- sess
			return sess, nil
		}
		dialed := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
			close(dialed)
		}()
		var firstSession, secondSession *mockSession
		Eventually(sessionChan).Should(Receive(&firstSession))
		firstSession.Close(handshake.ErrCloseSessionForRetry)
		Eventually(sessionChan).Should(Receive(&secondSession))
		secondSession.Close(errors.New("stop test"))
		Eventually(dialed).Should(BeClosed())
	})

	Context("handling packets", func() {
		It("handles packets", func() {
			ph := wire.Header{
				PacketNumber:    1,
				PacketNumberLen: protocol.PacketNumberLen2,
				ConnectionID:    0x1337,
			}
			b := &bytes.Buffer{}
			err := ph.Write(b, protocol.PerspectiveServer, cl.version)
			Expect(err).ToNot(HaveOccurred())
			packetConn.dataToRead <- b.Bytes()

			Expect(sess.packetCount).To(BeZero())
			stoppedListening := make(chan struct{})
			go func() {
				cl.listen()
				// it should continue listening when receiving valid packets
				close(stoppedListening)
			}()

			Eventually(func() int { return sess.packetCount }).Should(Equal(1))
			Expect(sess.closed).To(BeFalse())
			Consistently(stoppedListening).ShouldNot(BeClosed())
		})

		It("closes the session when encountering an error while reading from the connection", func() {
			testErr := errors.New("test error")
			packetConn.readErr = testErr
			cl.listen()
			Expect(sess.closed).To(BeTrue())
			Expect(sess.closeReason).To(MatchError(testErr))
		})
	})

	Context("Public Reset handling", func() {
		It("closes the session when receiving a Public Reset", func() {
			cl.handlePacket(addr, wire.WritePublicReset(cl.connectionID, 1, 0))
			Expect(cl.session.(*mockSession).closed).To(BeTrue())
			Expect(cl.session.(*mockSession).closedRemote).To(BeTrue())
			Expect(cl.session.(*mockSession).closeReason.(*qerr.QuicError).ErrorCode).To(Equal(qerr.PublicReset))
		})

		It("ignores Public Resets with the wrong connection ID", func() {
			cl.handlePacket(addr, wire.WritePublicReset(cl.connectionID+1, 1, 0))
			Expect(cl.session.(*mockSession).closed).To(BeFalse())
			Expect(cl.session.(*mockSession).closedRemote).To(BeFalse())
		})

		It("ignores Public Resets from the wrong remote address", func() {
			spoofedAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678}
			cl.handlePacket(spoofedAddr, wire.WritePublicReset(cl.connectionID, 1, 0))
			Expect(cl.session.(*mockSession).closed).To(BeFalse())
			Expect(cl.session.(*mockSession).closedRemote).To(BeFalse())
		})

		It("ignores unparseable Public Resets", func() {
			pr := wire.WritePublicReset(cl.connectionID, 1, 0)
			cl.handlePacket(addr, pr[:len(pr)-5])
			Expect(cl.session.(*mockSession).closed).To(BeFalse())
			Expect(cl.session.(*mockSession).closedRemote).To(BeFalse())
		})
	})
})
