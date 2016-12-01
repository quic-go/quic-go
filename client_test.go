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

	BeforeEach(func() {
		client = &Client{}
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
		client.session = &mockSession{}
		err = client.Close()
		Expect(err).ToNot(HaveOccurred())
		Expect(client.session.(*mockSession).closed).To(BeTrue())
	})
})
