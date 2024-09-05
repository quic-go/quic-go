package protocol

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Number", func() {
	It("InvalidPacketNumber is smaller than all valid packet numbers", func() {
		Expect(InvalidPacketNumber).To(BeNumerically("<", 0))
	})

	It("PacketNumberLen has the correct value", func() {
		Expect(PacketNumberLen1).To(BeEquivalentTo(1))
		Expect(PacketNumberLen2).To(BeEquivalentTo(2))
		Expect(PacketNumberLen3).To(BeEquivalentTo(3))
		Expect(PacketNumberLen4).To(BeEquivalentTo(4))
	})

	It("decodes the packet number", func() {
		Expect(DecodePacketNumber(PacketNumberLen1, 10, 255)).To(Equal(PacketNumber(255)))
		Expect(DecodePacketNumber(PacketNumberLen1, 10, 0)).To(Equal(PacketNumber(0)))
		Expect(DecodePacketNumber(PacketNumberLen1, 127, 0)).To(Equal(PacketNumber(256)))
		Expect(DecodePacketNumber(PacketNumberLen1, 128, 0)).To(Equal(PacketNumber(256)))
		Expect(DecodePacketNumber(PacketNumberLen1, 256+126, 0)).To(Equal(PacketNumber(256)))
		Expect(DecodePacketNumber(PacketNumberLen1, 256+127, 0)).To(Equal(PacketNumber(512)))
		Expect(DecodePacketNumber(PacketNumberLen2, 0xffff, 0xffff)).To(Equal(PacketNumber(0xffff)))
		Expect(DecodePacketNumber(PacketNumberLen2, 0xffff+1, 0xffff)).To(Equal(PacketNumber(0xffff)))

		// example from https://www.rfc-editor.org/rfc/rfc9000.html#section-a.3
		Expect(DecodePacketNumber(PacketNumberLen2, 0xa82f30ea, 0x9b32)).To(Equal(PacketNumber(0xa82f9b32)))
	})

	It("encodes the packet number, with the examples from the RFC", func() {
		Expect(PacketNumberLengthForHeader(1, InvalidPacketNumber)).To(Equal(PacketNumberLen2))
		Expect(PacketNumberLengthForHeader(1<<15-2, InvalidPacketNumber)).To(Equal(PacketNumberLen2))
		Expect(PacketNumberLengthForHeader(1<<15-1, InvalidPacketNumber)).To(Equal(PacketNumberLen3))
		Expect(PacketNumberLengthForHeader(1<<23-2, InvalidPacketNumber)).To(Equal(PacketNumberLen3))
		Expect(PacketNumberLengthForHeader(1<<23-1, InvalidPacketNumber)).To(Equal(PacketNumberLen4))
		Expect(PacketNumberLengthForHeader(1<<15+9, 10)).To(Equal(PacketNumberLen2))
		Expect(PacketNumberLengthForHeader(1<<15+10, 10)).To(Equal(PacketNumberLen3))
		Expect(PacketNumberLengthForHeader(1<<23+99, 100)).To(Equal(PacketNumberLen3))
		Expect(PacketNumberLengthForHeader(1<<23+100, 100)).To(Equal(PacketNumberLen4))
		// examples from https://www.rfc-editor.org/rfc/rfc9000.html#section-a.2
		Expect(PacketNumberLengthForHeader(0xac5c02, 0xabe8b3)).To(Equal(PacketNumberLen2))
		Expect(PacketNumberLengthForHeader(0xace8fe, 0xabe8b3)).To(Equal(PacketNumberLen3))
	})
})
