package frames

import (
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NackRange", func() {
	Context("Length", func() {
		It("calculates the length for a NACK range with only one packet", func() {
			nackRange := NackRange{FirstPacketNumber: 2, LastPacketNumber: 2}
			Expect(nackRange.Len()).To(Equal(uint64(0)))
		})

		It("calculates the length for a NACK range with more than one packet", func() {
			nackRange := NackRange{FirstPacketNumber: 10, LastPacketNumber: 20}
			Expect(nackRange.Len()).To(Equal(uint64(10)))
		})
	})

	Context("ContainsPacketNumber", func() {
		It("determines if a packet is in a NACK range with only one packet", func() {
			nackRange := NackRange{FirstPacketNumber: 2, LastPacketNumber: 2}
			Expect(nackRange.ContainsPacketNumber(protocol.PacketNumber(1))).To(BeFalse())
			Expect(nackRange.ContainsPacketNumber(protocol.PacketNumber(3))).To(BeFalse())
			Expect(nackRange.ContainsPacketNumber(protocol.PacketNumber(2))).To(BeTrue())
		})

		It("determines if a packet is in a NACK range with more than one packet", func() {
			nackRange := NackRange{FirstPacketNumber: 10, LastPacketNumber: 20}
			Expect(nackRange.ContainsPacketNumber(protocol.PacketNumber(1))).To(BeFalse())
			Expect(nackRange.ContainsPacketNumber(protocol.PacketNumber(10))).To(BeTrue())
			Expect(nackRange.ContainsPacketNumber(protocol.PacketNumber(15))).To(BeTrue())
			Expect(nackRange.ContainsPacketNumber(protocol.PacketNumber(20))).To(BeTrue())
			Expect(nackRange.ContainsPacketNumber(protocol.PacketNumber(21))).To(BeFalse())
		})
	})
})
