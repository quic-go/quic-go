package ackhandler

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AckHandler", func() {
	var handler *outgoingPacketAckHandler
	BeforeEach(func() {
		handler = NewOutgoingPacketAckHandler().(*outgoingPacketAckHandler)
	})

	Context("SentPacket", func() {
		It("accepts three consecutive packets", func() {
			entropy := EntropyAccumulator(0)
			packet1 := Packet{PacketNumber: 1, Plaintext: []byte{0x13, 0x37}, EntropyBit: true}
			packet2 := Packet{PacketNumber: 2, Plaintext: []byte{0xBE, 0xEF}, EntropyBit: true}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(2)))
			entropy.Add(packet1.PacketNumber, packet1.EntropyBit)
			Expect(handler.packetHistory[1].PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.packetHistory[1].Entropy).To(Equal(entropy))
			entropy.Add(packet2.PacketNumber, packet2.EntropyBit)
			Expect(handler.packetHistory[2].PacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.packetHistory[2].Entropy).To(Equal(entropy))
		})

		It("rejects packets with the same packet number", func() {
			packet1 := Packet{PacketNumber: 1, Plaintext: []byte{0x13, 0x37}, EntropyBit: true}
			packet2 := Packet{PacketNumber: 1, Plaintext: []byte{0xBE, 0xEF}, EntropyBit: false}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).To(HaveOccurred())
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
		})

		It("rejects non-consecutive packets", func() {
			packet1 := Packet{PacketNumber: 1, Plaintext: []byte{0x13, 0x37}, EntropyBit: true}
			packet2 := Packet{PacketNumber: 3, Plaintext: []byte{0xBE, 0xEF}, EntropyBit: false}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).To(HaveOccurred())
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(2)))
		})
	})

	Context("ACK handling", func() {
		var (
			packets []*Packet
		)
		BeforeEach(func() {
			packets = []*Packet{
				&Packet{PacketNumber: 1, Plaintext: []byte{0x13, 0x37}, EntropyBit: true},
				&Packet{PacketNumber: 2, Plaintext: []byte{0xBE, 0xEF}, EntropyBit: false},
				&Packet{PacketNumber: 3, Plaintext: []byte{0xCA, 0xFE}, EntropyBit: true},
				&Packet{PacketNumber: 4, Plaintext: []byte{0x54, 0x32}, EntropyBit: true},
				&Packet{PacketNumber: 5, Plaintext: []byte{0x54, 0x32}, EntropyBit: false},
				&Packet{PacketNumber: 6, Plaintext: []byte{0x54, 0x32}, EntropyBit: true},
			}
			for _, packet := range packets {
				handler.SentPacket(packet)
			}
		})

		It("rejects ACKs with a too high LargestObserved packet number", func() {
			ack := frames.AckFrame{
				LargestObserved: 1337,
			}
			err := handler.ReceivedAck(&ack)
			Expect(err).To(HaveOccurred())
			Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(0)))
		})

		Context("ACKs without NACK ranges", func() {
			It("handles an ACK with the correct entropy", func() {
				expectedEntropy := EntropyAccumulator(0)
				largestObserved := 4
				for i := 0; i < largestObserved; i++ {
					expectedEntropy.Add(packets[i].PacketNumber, packets[i].EntropyBit)
				}
				ack := frames.AckFrame{
					LargestObserved: protocol.PacketNumber(largestObserved),
					Entropy:         byte(expectedEntropy),
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(largestObserved)))
				Expect(handler.highestInOrderAckedEntropy).To(Equal(expectedEntropy))
				// all packets with packetNumbers smaller or equal largestObserved should be deleted
				Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(1)))
				Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(4)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(5)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(6)))
			})

			It("rejects an ACK with incorrect entropy", func() {
				ack := frames.AckFrame{
					LargestObserved: 3,
					Entropy:         0,
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).To(HaveOccurred())
				Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(0)))
				Expect(handler.highestInOrderAckedEntropy).To(Equal(EntropyAccumulator(0)))
				// nothing should be deleted from the packetHistory map
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(3)))
			})
		})
	})
})
