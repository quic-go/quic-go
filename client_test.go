package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"time"

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

		originalClientSessConstructor func(conn connection, hostname string, v protocol.VersionNumber, connectionID protocol.ConnectionID, tlsConf *tls.Config, config *Config, initialVersion protocol.VersionNumber, negotiatedVersions []protocol.VersionNumber) (packetHandler, <-chan handshakeEvent, error)
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
		msess, _, _ := newMockSession(nil, 0, 0, nil, nil, nil)
		sess = msess.(*mockSession)
		addr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
		packetConn = &mockPacketConn{
			addr:         &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
			dataReadFrom: addr,
		}
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
			) (packetHandler, <-chan handshakeEvent, error) {
				Expect(conn.Write([]byte("fake CHLO"))).To(Succeed())
				return sess, sess.handshakeChan, nil
			}
			origGenerateConnectionID = generateConnectionID
			generateConnectionID = func() (protocol.ConnectionID, error) {
				return cl.connectionID, nil
			}
		})

		AfterEach(func() {
			generateConnectionID = origGenerateConnectionID
		})

		It("dials non-forward-secure", func(done Done) {
			packetConn.dataToRead = acceptClientVersionPacket(cl.connectionID)
			dialed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				s, err := DialNonFWSecure(packetConn, addr, "quic.clemente.io:1337", nil, config)
				Expect(err).ToNot(HaveOccurred())
				Expect(s).ToNot(BeNil())
				close(dialed)
			}()
			Consistently(dialed).ShouldNot(BeClosed())
			sess.handshakeChan <- handshakeEvent{encLevel: protocol.EncryptionSecure}
			Eventually(dialed).Should(BeClosed())
			close(done)
		})

		It("dials a non-forward-secure address", func(done Done) {
			serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			Expect(err).ToNot(HaveOccurred())
			server, err := net.ListenUDP("udp", serverAddr)
			Expect(err).ToNot(HaveOccurred())
			defer server.Close()
			go func() {
				defer GinkgoRecover()
				for {
					_, clientAddr, err := server.ReadFromUDP(make([]byte, 200))
					if err != nil {
						return
					}
					_, err = server.WriteToUDP(acceptClientVersionPacket(cl.connectionID), clientAddr)
					Expect(err).ToNot(HaveOccurred())
				}
			}()

			dialed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				s, err := DialAddrNonFWSecure(server.LocalAddr().String(), nil, config)
				Expect(err).ToNot(HaveOccurred())
				Expect(s).ToNot(BeNil())
				close(dialed)
			}()
			Consistently(dialed).ShouldNot(BeClosed())
			sess.handshakeChan <- handshakeEvent{encLevel: protocol.EncryptionSecure}
			Eventually(dialed).Should(BeClosed())
			close(done)
		})

		It("Dial only returns after the handshake is complete", func(done Done) {
			packetConn.dataToRead = acceptClientVersionPacket(cl.connectionID)
			dialed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				s, err := Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
				Expect(err).ToNot(HaveOccurred())
				Expect(s).ToNot(BeNil())
				close(dialed)
			}()
			sess.handshakeChan <- handshakeEvent{encLevel: protocol.EncryptionSecure}
			Consistently(dialed).ShouldNot(BeClosed())
			close(sess.handshakeComplete)
			Eventually(dialed).Should(BeClosed())
			close(done)
		})

		It("resolves the address", func(done Done) {
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
			) (packetHandler, <-chan handshakeEvent, error) {
				remoteAddrChan <- conn.RemoteAddr().String()
				return sess, nil, nil
			}
			dialed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				DialAddr("localhost:17890", nil, &Config{HandshakeTimeout: time.Millisecond})
				close(dialed)
			}()
			Eventually(remoteAddrChan).Should(Receive(Equal("127.0.0.1:17890")))
			sess.Close(errors.New("peer doesn't reply"))
			Eventually(dialed).Should(BeClosed())
			close(done)
		})

		It("uses the tls.Config.ServerName as the hostname, if present", func(done Done) {
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
			) (packetHandler, <-chan handshakeEvent, error) {
				hostnameChan <- h
				return sess, nil, nil
			}
			dialed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				DialAddr("localhost:17890", &tls.Config{ServerName: "foobar"}, nil)
				close(dialed)
			}()
			Eventually(hostnameChan).Should(Receive(Equal("foobar")))
			sess.Close(errors.New("peer doesn't reply"))
			Eventually(dialed).Should(BeClosed())
			close(done)
		})

		It("returns an error that occurs during version negotiation", func(done Done) {
			testErr := errors.New("early handshake error")
			go func() {
				defer GinkgoRecover()
				_, dialErr := Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
				Expect(dialErr).To(MatchError(testErr))
				close(done)
			}()
			sess.Close(testErr)
		})

		It("returns an error that occurs while waiting for the connection to become secure", func(done Done) {
			testErr := errors.New("early handshake error")
			packetConn.dataToRead = acceptClientVersionPacket(cl.connectionID)
			go func() {
				defer GinkgoRecover()
				_, dialErr := Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
				Expect(dialErr).To(MatchError(testErr))
				close(done)
			}()
			sess.handshakeChan <- handshakeEvent{err: testErr}
		})

		It("returns an error that occurs while waiting for the handshake to complete", func(done Done) {
			testErr := errors.New("late handshake error")
			packetConn.dataToRead = acceptClientVersionPacket(cl.connectionID)
			go func() {
				defer GinkgoRecover()
				_, dialErr := Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
				Expect(dialErr).To(MatchError(testErr))
				close(done)
			}()
			sess.handshakeChan <- handshakeEvent{encLevel: protocol.EncryptionSecure}
			sess.handshakeComplete <- testErr
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

		It("errors when receiving an error from the connection", func(done Done) {
			testErr := errors.New("connection error")
			packetConn.readErr = testErr
			_, err := Dial(packetConn, addr, "quic.clemente.io:1337", nil, config)
			Expect(err).To(MatchError(testErr))
			close(done)
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
			) (packetHandler, <-chan handshakeEvent, error) {
				return nil, nil, testErr
			}
			_, err := DialNonFWSecure(packetConn, addr, "quic.clemente.io:1337", nil, config)
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
				packetConn.dataToRead = wire.ComposeGQUICVersionNegotiation(
					cl.connectionID,
					[]protocol.VersionNumber{newVersion},
				)
				sessionChan := make(chan *mockSession)
				handshakeChan := make(chan handshakeEvent)
				newClientSession = func(
					_ connection,
					_ string,
					_ protocol.VersionNumber,
					connectionID protocol.ConnectionID,
					_ *tls.Config,
					_ *Config,
					initialVersionP protocol.VersionNumber,
					negotiatedVersionsP []protocol.VersionNumber,
				) (packetHandler, <-chan handshakeEvent, error) {
					initialVersion = initialVersionP
					negotiatedVersions = negotiatedVersionsP
					// make the server accept the new version
					if len(negotiatedVersionsP) > 0 {
						packetConn.dataToRead = acceptClientVersionPacket(connectionID)
					}
					sess := &mockSession{
						connectionID: connectionID,
						stopRunLoop:  make(chan struct{}),
					}
					sessionChan <- sess
					return sess, handshakeChan, nil
				}

				established := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					err := cl.establishSecureConnection()
					Expect(err).ToNot(HaveOccurred())
					close(established)
				}()
				actualInitialVersion := cl.version
				var firstSession, secondSession *mockSession
				Eventually(sessionChan).Should(Receive(&firstSession))
				Eventually(sessionChan).Should(Receive(&secondSession))
				// it didn't pass the version negoation packet to the old session (since it has no payload)
				Expect(firstSession.packetCount).To(BeZero())
				Eventually(func() bool { return firstSession.closed }).Should(BeTrue())
				Expect(firstSession.closeReason).To(Equal(errCloseSessionForNewVersion))
				Consistently(func() bool { return secondSession.closed }).Should(BeFalse())
				Expect(cl.connectionID).ToNot(BeEquivalentTo(0x1337))
				Expect(negotiatedVersions).To(ContainElement(newVersion))
				Expect(initialVersion).To(Equal(actualInitialVersion))

				handshakeChan <- handshakeEvent{encLevel: protocol.EncryptionSecure}
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
				) (packetHandler, <-chan handshakeEvent, error) {
					atomic.AddUint32(&sessionCounter, 1)
					return sess, nil, nil
				}
				go cl.establishSecureConnection()
				Eventually(func() uint32 { return atomic.LoadUint32(&sessionCounter) }).Should(BeEquivalentTo(1))
				newVersion := protocol.VersionNumber(77)
				Expect(newVersion).ToNot(Equal(cl.version))
				Expect(config.Versions).To(ContainElement(newVersion))
				cl.handlePacket(nil, wire.ComposeGQUICVersionNegotiation(0x1337, []protocol.VersionNumber{newVersion}))
				Expect(atomic.LoadUint32(&sessionCounter)).To(BeEquivalentTo(2))
				newVersion = protocol.VersionNumber(78)
				Expect(newVersion).ToNot(Equal(cl.version))
				Expect(config.Versions).To(ContainElement(newVersion))
				cl.handlePacket(nil, wire.ComposeGQUICVersionNegotiation(0x1337, []protocol.VersionNumber{newVersion}))
				Expect(atomic.LoadUint32(&sessionCounter)).To(BeEquivalentTo(2))
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

	It("creates new sessions with the right parameters", func(done Done) {
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
		) (packetHandler, <-chan handshakeEvent, error) {
			cconn = connP
			hostname = hostnameP
			version = versionP
			conf = configP
			close(c)
			return sess, nil, nil
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
		Expect(version).To(Equal(cl.version))
		Expect(conf.Versions).To(Equal(config.Versions))
		sess.Close(errors.New("peer doesn't reply"))
		Eventually(dialed).Should(BeClosed())
		close(done)
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
			packetConn.dataToRead = b.Bytes()

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
