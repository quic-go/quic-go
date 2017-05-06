package quic

import (
	"bytes"
	"errors"
	"net"
	"reflect"
	"unsafe"

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
	)

	BeforeEach(func() {
		Eventually(areSessionsRunning).Should(BeFalse())
		packetConn = &mockPacketConn{}
		config = &Config{
			Versions: []protocol.VersionNumber{protocol.SupportedVersions[0], 77, 78},
		}
		addr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
		sess = &mockSession{connectionID: 0x1337}
		cl = &client{
			config:        config,
			connectionID:  0x1337,
			session:       sess,
			version:       protocol.SupportedVersions[0],
			conn:          &conn{pconn: packetConn, currentAddr: addr},
			errorChan:     make(chan struct{}),
			handshakeChan: make(chan struct{}),
		}
	})

	AfterEach(func() {
		if s, ok := cl.session.(*session); ok {
			s.Close(nil)
		}
		Eventually(areSessionsRunning).Should(BeFalse())
	})

	Context("Dialing", func() {
		PIt("creates a new client", func() {
			packetConn.dataToRead = []byte{0x0, 0x1, 0x0}
			sess, err := Dial(packetConn, addr, "quic.clemente.io:1337", config)
			Expect(err).ToNot(HaveOccurred())
			Expect(*(*[]protocol.VersionNumber)(unsafe.Pointer(reflect.ValueOf(sess.(*session).cryptoSetup).Elem().FieldByName("negotiatedVersions").UnsafeAddr()))).To(BeNil())
			Expect(*(*string)(unsafe.Pointer(reflect.ValueOf(sess.(*session).cryptoSetup).Elem().FieldByName("hostname").UnsafeAddr()))).To(Equal("quic.clemente.io"))
			sess.Close(nil)
		})

		It("uses all supported versions, if none are specified in the quic.Config", func() {
			c := populateClientConfig(&Config{})
			Expect(c.Versions).To(Equal(protocol.SupportedVersions))
		})

		It("errors when receiving an invalid first packet from the server", func() {
			packetConn.dataToRead = []byte{0xff}
			sess, err := Dial(packetConn, addr, "quic.clemente.io:1337", config)
			Expect(err).To(HaveOccurred())
			Expect(sess).To(BeNil())
		})

		It("errors when receiving an error from the connection", func() {
			testErr := errors.New("connection error")
			packetConn.readErr = testErr
			_, err := Dial(packetConn, addr, "quic.clemente.io:1337", config)
			Expect(err).To(MatchError(testErr))
		})
	})

	It("errors on invalid public header", func() {
		err := cl.handlePacket(nil, nil)
		Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.InvalidPacketHeader))
	})

	// this test requires a real session
	// and a real UDP conn (because it unblocks and errors when it is closed)
	PIt("properly closes", func(done Done) {
		Eventually(areSessionsRunning).Should(BeFalse())
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		Expect(err).ToNot(HaveOccurred())
		cl.conn = &conn{pconn: udpConn, currentAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}}
		err = cl.createNewSession(nil)
		Expect(err).ToNot(HaveOccurred())
		Eventually(areSessionsRunning).Should(BeTrue())

		var stoppedListening bool
		go func() {
			cl.listen()
			stoppedListening = true
		}()

		testErr := errors.New("test error")
		err = cl.session.Close(testErr)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() bool { return stoppedListening }).Should(BeTrue())
		Eventually(areSessionsRunning).Should(BeFalse())
		close(done)
	}, 10)

	It("creates new sessions with the right parameters", func() {
		cl.session = nil
		cl.hostname = "hostname"
		err := cl.createNewSession(nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(cl.session).ToNot(BeNil())
		Expect(cl.session.(*session).connectionID).To(Equal(cl.connectionID))
		Expect(cl.session.(*session).version).To(Equal(cl.version))
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
			Expect(cl.session).ToNot(Equal(sess))
			Expect(cl.connectionID).ToNot(Equal(0x1337)) // it generated a new connection ID
			Expect(err).ToNot(HaveOccurred())
			// it didn't pass the version negoation packet to the old session (since it has no payload)
			Expect(sess.packetCount).To(BeZero())
			// if the version negotiation packet was passed to the new session, it would end up as an undecryptable packet there
			Expect(cl.session.(*session).undecryptablePackets).To(BeEmpty())
			Expect(*(*[]protocol.VersionNumber)(unsafe.Pointer(reflect.ValueOf(cl.session.(*session).cryptoSetup).Elem().FieldByName("negotiatedVersions").UnsafeAddr()))).To(Equal([]protocol.VersionNumber{newVersion}))
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
