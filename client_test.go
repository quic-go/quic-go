package quic

import (
	"bytes"
	"errors"
	"net"

	"github.com/lucas-clemente/quic-go/protocol"
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

		originalClientSessConstructor func(conn connection, hostname string, v protocol.VersionNumber, connectionID protocol.ConnectionID, config *Config, negotiatedVersions []protocol.VersionNumber) (packetHandler, <-chan handshakeEvent, error)
	)

	BeforeEach(func() {
		originalClientSessConstructor = newClientSession
		Eventually(areSessionsRunning).Should(BeFalse())
		msess, _, _ := newMockSession(nil, 0, 0, nil, nil)
		sess = msess.(*mockSession)
		packetConn = &mockPacketConn{}
		config = &Config{
			Versions: []protocol.VersionNumber{protocol.SupportedVersions[0], 77, 78},
		}
		addr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
		cl = &client{
			config:       config,
			connectionID: 0x1337,
			session:      sess,
			version:      protocol.SupportedVersions[0],
			conn:         &conn{pconn: packetConn, currentAddr: addr},
			errorChan:    make(chan struct{}),
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
		BeforeEach(func() {
			newClientSession = func(
				_ connection,
				_ string,
				_ protocol.VersionNumber,
				_ protocol.ConnectionID,
				_ *Config,
				_ []protocol.VersionNumber,
			) (packetHandler, <-chan handshakeEvent, error) {
				return sess, sess.handshakeChan, nil
			}
		})

		It("dials non-forward-secure", func(done Done) {
			var dialedSess Session
			go func() {
				defer GinkgoRecover()
				var err error
				dialedSess, err = DialNonFWSecure(packetConn, addr, "quic.clemente.io:1337", config)
				Expect(err).ToNot(HaveOccurred())
			}()
			Consistently(func() Session { return dialedSess }).Should(BeNil())
			sess.handshakeChan <- handshakeEvent{encLevel: protocol.EncryptionSecure}
			Eventually(func() Session { return dialedSess }).ShouldNot(BeNil())
			close(done)
		})

		It("dials a non-forward-secure address", func(done Done) {
			var dialedSess Session
			go func() {
				defer GinkgoRecover()
				var err error
				dialedSess, err = DialAddrNonFWSecure("localhost:18901", config)
				Expect(err).ToNot(HaveOccurred())
			}()
			Consistently(func() Session { return dialedSess }).Should(BeNil())
			sess.handshakeChan <- handshakeEvent{encLevel: protocol.EncryptionSecure}
			Eventually(func() Session { return dialedSess }).ShouldNot(BeNil())
			close(done)
		})

		It("Dial only returns after the handshake is complete", func(done Done) {
			var dialedSess Session
			go func() {
				defer GinkgoRecover()
				var err error
				dialedSess, err = Dial(packetConn, addr, "quic.clemente.io:1337", config)
				Expect(err).ToNot(HaveOccurred())
			}()
			sess.handshakeChan <- handshakeEvent{encLevel: protocol.EncryptionSecure}
			Consistently(func() Session { return dialedSess }).Should(BeNil())
			close(sess.handshakeComplete)
			Eventually(func() Session { return dialedSess }).ShouldNot(BeNil())
			close(done)
		})

		It("resolves the address", func(done Done) {
			var cconn connection
			newClientSession = func(
				conn connection,
				_ string,
				_ protocol.VersionNumber,
				_ protocol.ConnectionID,
				_ *Config,
				_ []protocol.VersionNumber,
			) (packetHandler, <-chan handshakeEvent, error) {
				cconn = conn
				return sess, nil, nil
			}
			go DialAddr("localhost:17890", &Config{})
			Eventually(func() connection { return cconn }).ShouldNot(BeNil())
			Expect(cconn.RemoteAddr().String()).To(Equal("127.0.0.1:17890"))
			close(done)
		})

		It("returns an error that occurs while waiting for the connection to become secure", func(done Done) {
			testErr := errors.New("early handshake error")
			var dialErr error
			go func() {
				_, dialErr = Dial(packetConn, addr, "quic.clemente.io:1337", config)
			}()
			sess.handshakeChan <- handshakeEvent{err: testErr}
			Eventually(func() error { return dialErr }).Should(MatchError(testErr))
			close(done)
		})

		It("returns an error that occurs while waiting for the handshake to complete", func(done Done) {
			testErr := errors.New("late handshake error")
			var dialErr error
			go func() {
				_, dialErr = Dial(packetConn, addr, "quic.clemente.io:1337", config)
			}()
			sess.handshakeChan <- handshakeEvent{encLevel: protocol.EncryptionSecure}
			sess.handshakeComplete <- testErr
			Eventually(func() error { return dialErr }).Should(MatchError(testErr))
			close(done)
		})

		It("uses all supported versions, if none are specified in the quic.Config", func() {
			c := populateClientConfig(&Config{})
			Expect(c.Versions).To(Equal(protocol.SupportedVersions))
		})

		It("errors when receiving an invalid first packet from the server", func(done Done) {
			packetConn.dataToRead = []byte{0xff}
			_, err := Dial(packetConn, addr, "quic.clemente.io:1337", config)
			Expect(err).To(HaveOccurred())
			close(done)
		})

		It("errors when receiving an error from the connection", func(done Done) {
			testErr := errors.New("connection error")
			packetConn.readErr = testErr
			_, err := Dial(packetConn, addr, "quic.clemente.io:1337", config)
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
				_ *Config,
				_ []protocol.VersionNumber,
			) (packetHandler, <-chan handshakeEvent, error) {
				return nil, nil, testErr
			}
			_, err := DialNonFWSecure(packetConn, addr, "quic.clemente.io:1337", config)
			Expect(err).To(MatchError(testErr))
		})

		Context("version negotiation", func() {
			It("recognizes that a packet without VersionFlag means that the server accepted the suggested version", func() {
				ph := PublicHeader{
					PacketNumber:    1,
					PacketNumberLen: protocol.PacketNumberLen2,
					ConnectionID:    0x1337,
				}
				b := &bytes.Buffer{}
				err := ph.Write(b, protocol.VersionWhatever, protocol.PerspectiveServer)
				Expect(err).ToNot(HaveOccurred())
				err = cl.handlePacket(nil, b.Bytes())
				Expect(err).ToNot(HaveOccurred())
				Expect(cl.versionNegotiated).To(BeTrue())
			})

			It("changes the version after receiving a version negotiation packet", func() {
				var negotiatedVersions []protocol.VersionNumber
				newClientSession = func(
					_ connection,
					_ string,
					_ protocol.VersionNumber,
					connectionID protocol.ConnectionID,
					_ *Config,
					negotiatedVersionsP []protocol.VersionNumber,
				) (packetHandler, <-chan handshakeEvent, error) {
					negotiatedVersions = negotiatedVersionsP
					return &mockSession{
						connectionID: connectionID,
					}, nil, nil
				}

				newVersion := protocol.VersionNumber(77)
				Expect(config.Versions).To(ContainElement(newVersion))
				Expect(newVersion).ToNot(Equal(cl.version))
				Expect(sess.packetCount).To(BeZero())
				cl.connectionID = 0x1337
				err := cl.handlePacket(nil, composeVersionNegotiation(0x1337, []protocol.VersionNumber{newVersion}))
				Expect(err).ToNot(HaveOccurred())
				Expect(cl.version).To(Equal(newVersion))
				Expect(cl.versionNegotiated).To(BeTrue())
				// it swapped the sessions
				// Expect(cl.session).ToNot(Equal(sess))
				Expect(cl.connectionID).ToNot(Equal(0x1337)) // it generated a new connection ID
				Expect(err).ToNot(HaveOccurred())
				// it didn't pass the version negoation packet to the old session (since it has no payload)
				Expect(sess.packetCount).To(BeZero())
				Expect(negotiatedVersions).To(Equal([]protocol.VersionNumber{newVersion}))
			})

			It("errors if no matching version is found", func() {
				err := cl.handlePacket(nil, composeVersionNegotiation(0x1337, []protocol.VersionNumber{1}))
				Expect(err).To(MatchError(qerr.InvalidVersion))
			})

			It("errors if the version is supported by quic-go, but disabled by the quic.Config", func() {
				v := protocol.SupportedVersions[1]
				Expect(v).ToNot(Equal(cl.version))
				Expect(config.Versions).ToNot(ContainElement(v))
				err := cl.handlePacket(nil, composeVersionNegotiation(0x1337, []protocol.VersionNumber{v}))
				Expect(err).To(MatchError(qerr.InvalidVersion))
			})

			It("changes to the version preferred by the quic.Config", func() {
				err := cl.handlePacket(nil, composeVersionNegotiation(0x1337, []protocol.VersionNumber{config.Versions[2], config.Versions[1]}))
				Expect(err).ToNot(HaveOccurred())
				Expect(cl.version).To(Equal(config.Versions[1]))
			})

			It("ignores delayed version negotiation packets", func() {
				// if the version was not yet negotiated, handlePacket would return a VersionNegotiationMismatch error, see above test
				cl.versionNegotiated = true
				Expect(sess.packetCount).To(BeZero())
				err := cl.handlePacket(nil, composeVersionNegotiation(0x1337, []protocol.VersionNumber{1}))
				Expect(err).ToNot(HaveOccurred())
				Expect(cl.versionNegotiated).To(BeTrue())
				Expect(sess.packetCount).To(BeZero())
			})

			It("drops version negotiation packets that contain the offered version", func() {
				ver := cl.version
				err := cl.handlePacket(nil, composeVersionNegotiation(0x1337, []protocol.VersionNumber{ver}))
				Expect(err).ToNot(HaveOccurred())
				Expect(cl.version).To(Equal(ver))
			})
		})
	})

	It("errors on invalid public header", func() {
		err := cl.handlePacket(nil, nil)
		Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.InvalidPacketHeader))
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
			configP *Config,
			_ []protocol.VersionNumber,
		) (packetHandler, <-chan handshakeEvent, error) {
			cconn = connP
			hostname = hostnameP
			version = versionP
			conf = configP
			close(c)
			return sess, nil, nil
		}
		go func() {
			_, err := Dial(packetConn, addr, "quic.clemente.io:1337", config)
			Expect(err).ToNot(HaveOccurred())
		}()
		<-c
		Expect(cconn.(*conn).pconn).To(Equal(packetConn))
		Expect(hostname).To(Equal("quic.clemente.io"))
		Expect(version).To(Equal(cl.version))
		Expect(conf).To(Equal(config))
		close(done)
	})

	Context("handling packets", func() {
		It("handles packets", func() {
			ph := PublicHeader{
				PacketNumber:    1,
				PacketNumberLen: protocol.PacketNumberLen2,
				ConnectionID:    0x1337,
			}
			b := &bytes.Buffer{}
			err := ph.Write(b, protocol.Version36, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			packetConn.dataToRead = b.Bytes()

			Expect(sess.packetCount).To(BeZero())
			var stoppedListening bool
			go func() {
				cl.listen()
				// it should continue listening when receiving valid packets
				stoppedListening = true
			}()

			Eventually(func() int { return sess.packetCount }).Should(Equal(1))
			Expect(sess.closed).To(BeFalse())
			Consistently(func() bool { return stoppedListening }).Should(BeFalse())
		})

		It("closes the session when encountering an error while handling a packet", func() {
			Expect(sess.closeReason).ToNot(HaveOccurred())
			packetConn.dataToRead = bytes.Repeat([]byte{0xff}, 100)
			cl.listen()
			Expect(sess.closed).To(BeTrue())
			Expect(sess.closeReason).To(HaveOccurred())
		})

		It("closes the session when encountering an error while reading from the connection", func() {
			testErr := errors.New("test error")
			packetConn.readErr = testErr
			cl.listen()
			Expect(sess.closed).To(BeTrue())
			Expect(sess.closeReason).To(MatchError(testErr))
		})
	})
})
