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
		It("accepts two consecutive packets", func() {
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

		It("correctly calculates the entropy, even if the last packet has already been ACKed", func() {
			packet1 := Packet{PacketNumber: 1, Plaintext: []byte{0x13, 0x37}, EntropyBit: true}
			packet2 := Packet{PacketNumber: 2, Plaintext: []byte{0xBE, 0xEF}, EntropyBit: true}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			expectedEntropy := EntropyAccumulator(0)
			expectedEntropy.Add(packet1.PacketNumber, packet1.EntropyBit)
			ack := frames.AckFrame{
				LargestObserved: 1,
				Entropy:         byte(expectedEntropy),
			}
			err = handler.ReceivedAck(&ack)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(2)))
			expectedEntropy.Add(packet2.PacketNumber, packet2.EntropyBit)
			Expect(handler.packetHistory[2].Entropy).To(Equal(expectedEntropy))
		})
	})

	Context("ACK handling", func() {
		var (
			packets []*Packet
		)

		BeforeEach(func() {
			packets = []*Packet{
				&Packet{PacketNumber: 1, Plaintext: []byte{0x13, 0x37}, EntropyBit: true},
				&Packet{PacketNumber: 2, Plaintext: []byte{0xBE, 0xEF}, EntropyBit: true},
				&Packet{PacketNumber: 3, Plaintext: []byte{0xCA, 0xFE}, EntropyBit: true},
				&Packet{PacketNumber: 4, Plaintext: []byte{0x54, 0x32}, EntropyBit: true},
				&Packet{PacketNumber: 5, Plaintext: []byte{0x54, 0x32}, EntropyBit: true},
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
				Expect(err).To(Equal(errEntropy))
				Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(0)))
				Expect(handler.highestInOrderAckedEntropy).To(Equal(EntropyAccumulator(0)))
				// nothing should be deleted from the packetHistory map
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(3)))
			})

			It("checks the entropy after an previous ACK was already received", func() {
				expectedEntropy := EntropyAccumulator(0)
				expectedEntropy.Add(1, packets[0].EntropyBit)
				ack := frames.AckFrame{
					LargestObserved: 1,
					Entropy:         byte(expectedEntropy),
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				expectedEntropy.Add(2, packets[1].EntropyBit)
				ack = frames.AckFrame{
					LargestObserved: 2,
					Entropy:         byte(expectedEntropy),
				}
				err = handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
			})

			It("checks the entropy of an ACK after a previous ACK was already received", func() {
				expectedEntropy := EntropyAccumulator(0)
				expectedEntropy.Add(1, packets[0].EntropyBit)
				ack := frames.AckFrame{
					LargestObserved: 1,
					Entropy:         byte(expectedEntropy),
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				expectedEntropy.Add(2, packets[1].EntropyBit)
				expectedEntropy.Add(3, packets[2].EntropyBit)
				ack = frames.AckFrame{
					LargestObserved: 3,
					Entropy:         byte(expectedEntropy),
				}
				err = handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("ACKs with NACK ranges", func() {
			It("handles an ACK with one NACK range and one missing packet", func() {
				nackRange := frames.NackRange{FirstPacketNumber: 2, LastPacketNumber: 2}
				entropy := EntropyAccumulator(0)
				entropy.Add(packets[0].PacketNumber, packets[0].EntropyBit) // Packet 1
				entropy.Add(packets[2].PacketNumber, packets[2].EntropyBit) // Packet 3
				ack := frames.AckFrame{
					LargestObserved: 3,
					Entropy:         byte(entropy),
					NackRanges:      []frames.NackRange{nackRange},
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(1)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(2)))
				Expect(handler.packetHistory[2].MissingReports).To(Equal(uint8(1)))
				// Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(3)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(4)))
			})

			It("handles an ACK with one NACK range and two missing packets", func() {
				nackRange := frames.NackRange{FirstPacketNumber: 2, LastPacketNumber: 3}
				entropy := EntropyAccumulator(0)
				entropy.Add(packets[0].PacketNumber, packets[0].EntropyBit) // Packet 1
				entropy.Add(packets[3].PacketNumber, packets[3].EntropyBit) // Packet 4
				ack := frames.AckFrame{
					LargestObserved: 4,
					Entropy:         byte(entropy),
					NackRanges:      []frames.NackRange{nackRange},
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(1)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(2)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(3)))
				Expect(handler.packetHistory[2].MissingReports).To(Equal(uint8(1)))
				Expect(handler.packetHistory[3].MissingReports).To(Equal(uint8(1)))
				// Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(4)))
			})

			It("handles an ACK with multiple NACK ranges", func() {
				nackRanges := []frames.NackRange{
					frames.NackRange{FirstPacketNumber: 4, LastPacketNumber: 4},
					frames.NackRange{FirstPacketNumber: 2, LastPacketNumber: 2},
				}
				entropy := EntropyAccumulator(0)
				entropy.Add(packets[0].PacketNumber, packets[0].EntropyBit) // Packet 1
				entropy.Add(packets[2].PacketNumber, packets[2].EntropyBit) // Packet 3
				entropy.Add(packets[4].PacketNumber, packets[4].EntropyBit) // Packet 5
				ack := frames.AckFrame{
					LargestObserved: 5,
					Entropy:         byte(entropy),
					NackRanges:      nackRanges,
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(1)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(2)))
				Expect(handler.packetHistory[2].MissingReports).To(Equal(uint8(1)))
				// Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(3)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(4)))
				Expect(handler.packetHistory[4].MissingReports).To(Equal(uint8(1)))
				// Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(5)))
			})

			It("rejects an ACK with a NACK that has incorrect entropy", func() {
				nackRange := frames.NackRange{FirstPacketNumber: 2, LastPacketNumber: 3}
				entropy := EntropyAccumulator(0)
				entropy.Add(packets[0].PacketNumber, packets[0].EntropyBit) // Packet 1
				entropy.Add(packets[3].PacketNumber, packets[3].EntropyBit) // Packet 4
				ack := frames.AckFrame{
					LargestObserved: 4,
					Entropy:         byte(entropy + 1),
					NackRanges:      []frames.NackRange{nackRange},
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(errEntropy))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(2)))
			})

			It("checks the entropy of an ACK with a NACK after a previous ACK was already received", func() {
				expectedEntropy := EntropyAccumulator(0)
				expectedEntropy.Add(1, packets[0].EntropyBit)
				ack := frames.AckFrame{
					LargestObserved: 1,
					Entropy:         byte(expectedEntropy),
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				expectedEntropy.Add(4, packets[3].EntropyBit)
				nackRange := frames.NackRange{FirstPacketNumber: 2, LastPacketNumber: 3}
				ack = frames.AckFrame{
					LargestObserved: 4,
					Entropy:         byte(expectedEntropy),
					NackRanges:      []frames.NackRange{nackRange},
				}
				err = handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
			})

			It("increments the missingReports counter every time a NACK for a packet is received", func() {
				nackRange1 := frames.NackRange{FirstPacketNumber: 4, LastPacketNumber: 4}
				nackRange2 := frames.NackRange{FirstPacketNumber: 2, LastPacketNumber: 2}
				entropy := EntropyAccumulator(0)
				entropy.Add(1, packets[0].EntropyBit)
				entropy.Add(3, packets[2].EntropyBit)
				ack1 := frames.AckFrame{
					LargestObserved: 3,
					Entropy:         byte(entropy),
					NackRanges:      []frames.NackRange{nackRange2},
				}
				err := handler.ReceivedAck(&ack1)
				Expect(err).ToNot(HaveOccurred())
				entropy.Add(5, packets[4].EntropyBit)
				ack2 := frames.AckFrame{
					LargestObserved: 5,
					Entropy:         byte(entropy),
					NackRanges:      []frames.NackRange{nackRange1, nackRange2},
				}
				err = handler.ReceivedAck(&ack2)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(2)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(4)))
				Expect(handler.packetHistory[2].MissingReports).To(Equal(uint8(2)))
				Expect(handler.packetHistory[4].MissingReports).To(Equal(uint8(1)))
			})
		})

		Context("Retransmission handler", func() {
			It("queues a packet for retransmission", func() {
				retransmissionThreshold = 1
				nackRange1 := frames.NackRange{FirstPacketNumber: 4, LastPacketNumber: 4}
				nackRange2 := frames.NackRange{FirstPacketNumber: 2, LastPacketNumber: 2}
				entropy := EntropyAccumulator(0)
				entropy.Add(1, packets[0].EntropyBit)
				entropy.Add(3, packets[2].EntropyBit)
				ack1 := frames.AckFrame{
					LargestObserved: 3,
					Entropy:         byte(entropy),
					NackRanges:      []frames.NackRange{nackRange2},
				}
				err := handler.ReceivedAck(&ack1)
				Expect(err).ToNot(HaveOccurred())
				entropy.Add(5, packets[4].EntropyBit)
				ack2 := frames.AckFrame{
					LargestObserved: 5,
					Entropy:         byte(entropy),
					NackRanges:      []frames.NackRange{nackRange1, nackRange2},
				}
				err = handler.ReceivedAck(&ack2)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(handler.retransmissionQueue)).To(Equal(1))
				Expect(handler.retransmissionQueue[0].PacketNumber).To(Equal(protocol.PacketNumber(2)))
			})
		})
	})
})
