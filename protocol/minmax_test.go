package protocol_test

import (
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("minmax", func() {
	It("calculates packet number max", func() {
		Expect(protocol.MaxPacketNumber(1, 2)).To(Equal(protocol.PacketNumber(2)))
		Expect(protocol.MaxPacketNumber(2, 1)).To(Equal(protocol.PacketNumber(2)))
	})

	It("calculates packet number min", func() {
		Expect(protocol.MinPacketNumber(1, 2)).To(Equal(protocol.PacketNumber(1)))
		Expect(protocol.MinPacketNumber(2, 1)).To(Equal(protocol.PacketNumber(1)))
	})
})
