package quic

import (
	"bytes"
	"net"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client", func() {
	var client *Client
	var session *mockSession

	BeforeEach(func() {
		client = &Client{}
		session = &mockSession{}
		client.session = session
	})

	It("errors on invalid public header", func() {
		err := client.handlePacket(nil)
		Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.InvalidPacketHeader))
	})

	It("errors on large packets", func() {
		err := client.handlePacket(bytes.Repeat([]byte{'a'}, int(protocol.MaxPacketSize)+1))
		Expect(err).To(MatchError(qerr.PacketTooLarge))
	})

	It("closes sessions when Close is called", func() {
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		client.conn, err = net.ListenUDP("udp", addr)
		Expect(err).ToNot(HaveOccurred())
		err = client.Close()
		Expect(err).ToNot(HaveOccurred())
		Expect(session.closed).To(BeTrue())
		Expect(session.closeReason).To(BeNil())
	})

	Context("handling packets", func() {
		It("errors on too large packets", func() {
			err := client.handlePacket(bytes.Repeat([]byte{'f'}, int(protocol.MaxPacketSize+1)))
			Expect(err).To(MatchError(qerr.PacketTooLarge))
		})

		It("handles packets", func(done Done) {
			var err error
			client.addr, err = net.ResolveUDPAddr("udp", "127.0.0.1:0")
			Expect(err).ToNot(HaveOccurred())
			client.conn, err = net.ListenUDP("udp", client.addr)
			Expect(err).NotTo(HaveOccurred())
			serverConn, err := net.DialUDP("udp", nil, client.conn.LocalAddr().(*net.UDPAddr))
			Expect(err).NotTo(HaveOccurred())

			go func() {
				defer GinkgoRecover()
				listenErr := client.Listen()
				Expect(listenErr).ToNot(HaveOccurred())
				close(done)
			}()

			Expect(session.packetCount).To(BeZero())
			ph := PublicHeader{
				PacketNumber:    1,
				PacketNumberLen: protocol.PacketNumberLen2,
				ConnectionID:    0x1337,
			}
			b := &bytes.Buffer{}
			err = ph.Write(b, protocol.Version36, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			_, err = serverConn.Write(b.Bytes())
			Expect(err).ToNot(HaveOccurred())

			Eventually(func() int { return session.packetCount }).Should(Equal(1))
			Expect(session.closed).To(BeFalse())

			err = client.Close()
			Expect(err).ToNot(HaveOccurred())
		})

		It("closes the session when encountering an error while handling a packet", func(done Done) {
			var err error
			client.addr, err = net.ResolveUDPAddr("udp", "127.0.0.1:0")
			Expect(err).ToNot(HaveOccurred())
			client.conn, err = net.ListenUDP("udp", client.addr)
			Expect(err).NotTo(HaveOccurred())
			serverConn, err := net.DialUDP("udp", nil, client.conn.LocalAddr().(*net.UDPAddr))
			Expect(err).NotTo(HaveOccurred())

			var listenErr error
			go func() {
				defer GinkgoRecover()
				listenErr = client.Listen()
				Expect(listenErr).To(HaveOccurred())
				close(done)
			}()

			// cause a PacketTooLarge error
			_, err = serverConn.Write(bytes.Repeat([]byte{'f'}, 100))
			Expect(err).ToNot(HaveOccurred())

			Eventually(func() bool { return session.closed }).Should(BeTrue())
			Expect(session.closeReason).To(MatchError(listenErr))

			err = client.Close()
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
