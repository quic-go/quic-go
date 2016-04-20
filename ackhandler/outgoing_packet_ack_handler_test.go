package ackhandler

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AckHandler", func() {
	Context("SentPacket", func() {
		It("accepts two consecutive packets", func() {
			packet1 := Packet{PacketNumber: 1, Plaintext: []byte{0x13, 0x37}, EntropyBit: true}
			packet2 := Packet{PacketNumber: 2, Plaintext: []byte{0xBE, 0xEF}, EntropyBit: false}
			handler := NewOutgoingPacketAckHandler()
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).ToNot(HaveOccurred())
		})

		It("rejects two packets with the same packet number", func() {
			packet1 := Packet{PacketNumber: 1, Plaintext: []byte{0x13, 0x37}, EntropyBit: true}
			packet2 := Packet{PacketNumber: 1, Plaintext: []byte{0xBE, 0xEF}, EntropyBit: false}
			handler := NewOutgoingPacketAckHandler()
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).To(HaveOccurred())
		})

		It("rejects non-consecutive packets", func() {
			packet1 := Packet{PacketNumber: 1, Plaintext: []byte{0x13, 0x37}, EntropyBit: true}
			packet2 := Packet{PacketNumber: 3, Plaintext: []byte{0xBE, 0xEF}, EntropyBit: false}
			handler := NewOutgoingPacketAckHandler()
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).To(HaveOccurred())
		})
	})
})
