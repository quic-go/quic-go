package quic

import (
	"bytes"
	"encoding/binary"
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
		cl                              *client
		config                          *Config
		sess                            *mockSession
		packetConn                      *mockPacketConn
		addr                            net.Addr
		versionNegotiateConnStateCalled bool
	)

	BeforeEach(func() {
		Eventually(areSessionsRunning).Should(BeFalse())
		versionNegotiateConnStateCalled = false
		packetConn = &mockPacketConn{}
		config = &Config{
			ConnState: func(_ Session, state ConnState) {
				if state == ConnStateVersionNegotiated {
					versionNegotiateConnStateCalled = true
				}
			},
		}
		addr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
		sess = &mockSession{connectionID: 0x1337}
		cl = &client{
			config:       config,
			connectionID: 0x1337,
			session:      sess,
			version:      protocol.Version36,
			conn:         &conn{pconn: packetConn, currentAddr: addr},
		}
	})

	AfterEach(func() {
		if s, ok := cl.session.(*session); ok {
			s.Close(nil)
		}
		Eventually(areSessionsRunning).Should(BeFalse())
	})

	Context("Dialing", func() {
		It("creates a new client", func() {
			packetConn.dataToRead = []byte{0x0, 0x1, 0x0}
			var err error
			sess, err := Dial(packetConn, addr, "quic.clemente.io:1337", config)
			Expect(err).ToNot(HaveOccurred())
			Expect(*(*[]protocol.VersionNumber)(unsafe.Pointer(reflect.ValueOf(sess.(*session).cryptoSetup).Elem().FieldByName("negotiatedVersions").UnsafeAddr()))).To(BeNil())
			Expect(*(*string)(unsafe.Pointer(reflect.ValueOf(sess.(*session).cryptoSetup).Elem().FieldByName("hostname").UnsafeAddr()))).To(Equal("quic.clemente.io"))
			sess.Close(nil)
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

		// now we're only testing that Dial doesn't return directly after version negotiation
		PIt("doesn't return after version negotiation is established if no ConnState is defined", func() {
			// TODO(#506): Fix test
			packetConn.dataToRead = []byte{0x0, 0x1, 0x0}
			config.ConnState = nil
			var dialReturned bool
			go func() {
				defer GinkgoRecover()
				_, err := Dial(packetConn, addr, "quic.clemente.io:1337", config)
				Expect(err).ToNot(HaveOccurred())
				dialReturned = true
			}()
			Consistently(func() bool { return dialReturned }).Should(BeFalse())
		})

		It("only establishes a connection once it is forward-secure if no ConnState is defined", func() {
			config.ConnState = nil
			client := &client{conn: &conn{pconn: packetConn, currentAddr: addr}, config: config}
			client.connStateChangeOrErrCond.L = &client.mutex
			var returned bool
			go func() {
				defer GinkgoRecover()
				_, err := client.establishConnection()
				Expect(err).ToNot(HaveOccurred())
				returned = true
			}()
			Consistently(func() bool { return returned }).Should(BeFalse())
			// switch to a secure connection
			client.cryptoChangeCallback(nil, false)
			Consistently(func() bool { return returned }).Should(BeFalse())
			// switch to a forward-secure connection
			client.cryptoChangeCallback(nil, true)
			Eventually(func() bool { return returned }).Should(BeTrue())
		})
	})

	It("errors on invalid public header", func() {
		err := cl.handlePacket(nil, nil)
		Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.InvalidPacketHeader))
	})

	// this test requires a real session (because it calls the close callback) and a real UDP conn (because it unblocks and errors when it is closed)
	It("properly closes", func(done Done) {
		Eventually(areSessionsRunning).Should(BeFalse())
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		Expect(err).ToNot(HaveOccurred())
		cl.conn = &conn{pconn: udpConn}
		err = cl.createNewSession(nil)
		Expect(err).NotTo(HaveOccurred())
		testErr := errors.New("test error")
		Eventually(areSessionsRunning).Should(BeTrue())

		var stoppedListening bool
		go func() {
			cl.listen()
			stoppedListening = true
		}()

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
		getVersionNegotiation := func(versions []protocol.VersionNumber) []byte {
			oldVersionNegotiationPacket := composeVersionNegotiation(0x1337)
			oldSupportVersionTags := protocol.SupportedVersionsAsTags
			var b bytes.Buffer
			for _, v := range versions {
				s := make([]byte, 4)
				binary.LittleEndian.PutUint32(s, protocol.VersionNumberToTag(v))
				b.Write(s)
			}
			protocol.SupportedVersionsAsTags = b.Bytes()
			packet := composeVersionNegotiation(cl.connectionID)
			protocol.SupportedVersionsAsTags = oldSupportVersionTags
			Expect(composeVersionNegotiation(0x1337)).To(Equal(oldVersionNegotiationPacket))
			return packet
		}

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
			Expect(cl.connState).To(Equal(ConnStateVersionNegotiated))
			Eventually(func() bool { return versionNegotiateConnStateCalled }).Should(BeTrue())
		})

		It("changes the version after receiving a version negotiation packet", func() {
			newVersion := protocol.Version35
			Expect(newVersion).ToNot(Equal(cl.version))
			Expect(sess.packetCount).To(BeZero())
			cl.connectionID = 0x1337
			err := cl.handlePacket(nil, getVersionNegotiation([]protocol.VersionNumber{newVersion}))
			Expect(cl.version).To(Equal(newVersion))
			Expect(cl.connState).To(Equal(ConnStateVersionNegotiated))
			Eventually(func() bool { return versionNegotiateConnStateCalled }).Should(BeTrue())
			// it swapped the sessions
			Expect(cl.session).ToNot(Equal(sess))
			Expect(cl.connectionID).ToNot(Equal(0x1337)) // it generated a new connection ID
			Expect(err).ToNot(HaveOccurred())
			// it didn't pass the version negoation packet to the session (since it has no payload)
			Expect(sess.packetCount).To(BeZero())
			Expect(*(*[]protocol.VersionNumber)(unsafe.Pointer(reflect.ValueOf(cl.session.(*session).cryptoSetup).Elem().FieldByName("negotiatedVersions").UnsafeAddr()))).To(Equal([]protocol.VersionNumber{35}))
		})

		It("errors if no matching version is found", func() {
			err := cl.handlePacket(nil, getVersionNegotiation([]protocol.VersionNumber{1}))
			Expect(err).To(MatchError(qerr.InvalidVersion))
		})

		It("ignores delayed version negotiation packets", func() {
			// if the version was not yet negotiated, handlePacket would return a VersionNegotiationMismatch error, see above test
			cl.connState = ConnStateVersionNegotiated
			Expect(sess.packetCount).To(BeZero())
			err := cl.handlePacket(nil, getVersionNegotiation([]protocol.VersionNumber{1}))
			Expect(err).ToNot(HaveOccurred())
			Expect(cl.connState).To(Equal(ConnStateVersionNegotiated))
			Expect(sess.packetCount).To(BeZero())
			Consistently(func() bool { return versionNegotiateConnStateCalled }).Should(BeFalse())
		})

		It("errors if the server should have accepted the offered version", func() {
			err := cl.handlePacket(nil, getVersionNegotiation([]protocol.VersionNumber{cl.version}))
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidVersionNegotiationPacket, "Server already supports client's version and should have accepted the connection.")))
		})
	})
})
