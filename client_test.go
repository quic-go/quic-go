package quic

import (
	"bytes"

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
})
