package quic

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"runtime"
	"time"
	"unsafe"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client", func() {
	var (
		client                         *Client
		sess                           *mockSession
		packetConn                     *mockPacketConn
		versionNegotiateCallbackCalled bool
	)

	BeforeEach(func() {
		packetConn = &mockPacketConn{}
		versionNegotiateCallbackCalled = false
		client = &Client{
			versionNegotiateCallback: func() error {
				versionNegotiateCallbackCalled = true
				return nil
			},
		}
		addr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
		sess = &mockSession{connectionID: 0x1337}
		client.connectionID = 0x1337
		client.session = sess
		client.version = protocol.Version36
		client.conn = &conn{pconn: packetConn, currentAddr: addr}
	})

	It("creates a new client", func() {
		var err error
		client, err = NewClient("quic.clemente.io:1337", nil, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(client.hostname).To(Equal("quic.clemente.io"))
		Expect(*(*[]protocol.VersionNumber)(unsafe.Pointer(reflect.ValueOf(client.session.(*session).cryptoSetup).Elem().FieldByName("negotiatedVersions").UnsafeAddr()))).To(BeNil())
	})

	It("errors on invalid public header", func() {
		err := client.handlePacket(nil, nil)
		Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.InvalidPacketHeader))
	})

	It("errors on large packets", func() {
		err := client.handlePacket(nil, bytes.Repeat([]byte{'a'}, int(protocol.MaxPacketSize)+1))
		Expect(err).To(MatchError(qerr.PacketTooLarge))
	})

	PIt("properly closes the client", func(done Done) {
		testErr := errors.New("test error")
		time.Sleep(10 * time.Millisecond) // Wait for old goroutines to finish
		numGoRoutines := runtime.NumGoroutine()

		var stoppedListening bool
		go func() {
			defer GinkgoRecover()
			err := client.Listen()
			Expect(err).ToNot(HaveOccurred())
			stoppedListening = true
		}()

		err := client.Close(testErr)
		Expect(err).ToNot(HaveOccurred())
		Eventually(sess.closed).Should(BeTrue())
		Expect(sess.closeReason).To(MatchError(testErr))
		Expect(client.closed).To(Equal(uint32(1)))
		Eventually(func() bool { return stoppedListening }).Should(BeTrue())
		Eventually(runtime.NumGoroutine()).Should(Equal(numGoRoutines))
		close(done)
	}, 10)

	It("only closes the client once", func() {
		client.closed = 1
		err := client.Close(errors.New("test error"))
		Expect(err).ToNot(HaveOccurred())
		Eventually(sess.closed).Should(BeFalse())
		Expect(sess.closeReason).ToNot(HaveOccurred())
	})

	It("creates new sessions with the right parameters", func() {
		client.session = nil
		client.hostname = "hostname"
		err := client.createNewSession(nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(client.session).ToNot(BeNil())
		Expect(client.session.(*session).connectionID).To(Equal(client.connectionID))
		Expect(client.session.(*session).version).To(Equal(client.version))

		err = client.Close(nil)
		Expect(err).ToNot(HaveOccurred())
	})

	It("opens a stream", func() {
		stream, err := client.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(stream).ToNot(BeNil())
	})

	Context("handling packets", func() {
		It("errors on too large packets", func() {
			err := client.handlePacket(nil, bytes.Repeat([]byte{'f'}, int(protocol.MaxPacketSize+1)))
			Expect(err).To(MatchError(qerr.PacketTooLarge))
		})

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
				_ = client.Listen()
				// it should continue listening when receiving valid packets
				stoppedListening = true
			}()

			Eventually(func() int { return sess.packetCount }).Should(Equal(1))
			Expect(sess.closed).To(BeFalse())
			Consistently(func() bool { return stoppedListening }).Should(BeFalse())
		})

		It("closes the session when encountering an error while handling a packet", func() {
			packetConn.dataToRead = bytes.Repeat([]byte{0xff}, 100)
			listenErr := client.Listen()
			Expect(listenErr).To(HaveOccurred())
			Expect(sess.closed).To(BeTrue())
			Expect(sess.closeReason).To(MatchError(listenErr))
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
			packet := composeVersionNegotiation(client.connectionID)
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
			err = client.handlePacket(nil, b.Bytes())
			Expect(err).ToNot(HaveOccurred())
			Expect(client.versionNegotiated).To(BeTrue())
			Expect(versionNegotiateCallbackCalled).To(BeTrue())
		})

		It("changes the version after receiving a version negotiation packet", func() {
			newVersion := protocol.Version35
			Expect(newVersion).ToNot(Equal(client.version))
			Expect(sess.packetCount).To(BeZero())
			client.connectionID = 0x1337
			err := client.handlePacket(nil, getVersionNegotiation([]protocol.VersionNumber{newVersion}))
			Expect(client.version).To(Equal(newVersion))
			Expect(client.versionNegotiated).To(BeTrue())
			Expect(versionNegotiateCallbackCalled).To(BeTrue())
			// it swapped the sessions
			Expect(client.session).ToNot(Equal(sess))
			Expect(client.connectionID).ToNot(Equal(0x1337)) // it generated a new connection ID
			Expect(err).ToNot(HaveOccurred())
			// it didn't pass the version negoation packet to the session (since it has no payload)
			Expect(sess.packetCount).To(BeZero())
			Expect(*(*[]protocol.VersionNumber)(unsafe.Pointer(reflect.ValueOf(client.session.(*session).cryptoSetup).Elem().FieldByName("negotiatedVersions").UnsafeAddr()))).To(Equal([]protocol.VersionNumber{35}))

			err = client.Close(nil)
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors if no matching version is found", func() {
			err := client.handlePacket(nil, getVersionNegotiation([]protocol.VersionNumber{1}))
			Expect(err).To(MatchError(qerr.InvalidVersion))
		})

		It("ignores delayed version negotiation packets", func() {
			// if the version was not yet negotiated, handlePacket would return a VersionNegotiationMismatch error, see above test
			client.versionNegotiated = true
			Expect(sess.packetCount).To(BeZero())
			err := client.handlePacket(nil, getVersionNegotiation([]protocol.VersionNumber{1}))
			Expect(err).ToNot(HaveOccurred())
			Expect(client.versionNegotiated).To(BeTrue())
			Expect(sess.packetCount).To(BeZero())
			Expect(versionNegotiateCallbackCalled).To(BeFalse())
		})

		It("errors if the server should have accepted the offered version", func() {
			err := client.handlePacket(nil, getVersionNegotiation([]protocol.VersionNumber{client.version}))
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidVersionNegotiationPacket, "Server already supports client's version and should have accepted the connection.")))
		})
	})
})
