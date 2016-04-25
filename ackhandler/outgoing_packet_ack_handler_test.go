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
			entropy := EntropyAccumulator(0)
			entropy.Add(packet1.PacketNumber, packet1.EntropyBit)
			ack := frames.AckFrame{
				LargestObserved: 1,
				Entropy:         byte(entropy),
			}
			err = handler.ReceivedAck(&ack)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(2)))
			entropy.Add(packet2.PacketNumber, packet2.EntropyBit)
			Expect(handler.packetHistory[2].Entropy).To(Equal(entropy))
		})
	})

	Context("ACK entropy calculations", func() {
		var packets []*Packet
		var entropy EntropyAccumulator

		BeforeEach(func() {
			entropy = EntropyAccumulator(0)
			packets = []*Packet{
				&Packet{PacketNumber: 1, Plaintext: []byte{0x13, 0x37}, EntropyBit: true},
				&Packet{PacketNumber: 2, Plaintext: []byte{0xBE, 0xEF}, EntropyBit: true},
				&Packet{PacketNumber: 3, Plaintext: []byte{0xCA, 0xFE}, EntropyBit: true},
				&Packet{PacketNumber: 4, Plaintext: []byte{0x54, 0x32}, EntropyBit: true},
				&Packet{PacketNumber: 5, Plaintext: []byte{0x12, 0x42}, EntropyBit: true},
				&Packet{PacketNumber: 6, Plaintext: []byte{0xCA, 0xFE}, EntropyBit: true},
			}
			for _, packet := range packets {
				handler.SentPacket(packet)
			}
		})

		It("no NACK ranges", func() {
			largestObserved := 5
			for i := 0; i < largestObserved; i++ {
				entropy.Add(packets[i].PacketNumber, packets[i].EntropyBit)
			}
			ack := frames.AckFrame{LargestObserved: protocol.PacketNumber(largestObserved)}
			calculatedEntropy, err := handler.calculateExpectedEntropy(&ack)
			Expect(err).ToNot(HaveOccurred())
			Expect(calculatedEntropy).To(Equal(entropy))
		})

		It("one NACK ranges", func() {
			largestObserved := 5
			for i := 0; i < largestObserved; i++ {
				if i == 2 || i == 3 { // skip Packet 3 and 4
					continue
				}
				entropy.Add(packets[i].PacketNumber, packets[i].EntropyBit)
			}
			ack := frames.AckFrame{
				LargestObserved: protocol.PacketNumber(largestObserved),
				NackRanges:      []frames.NackRange{frames.NackRange{FirstPacketNumber: 3, LastPacketNumber: 4}},
			}
			calculatedEntropy, err := handler.calculateExpectedEntropy(&ack)
			Expect(err).ToNot(HaveOccurred())
			Expect(calculatedEntropy).To(Equal(entropy))
		})

		It("one NACK ranges, when some packages have already been ACKed", func() {
			largestObserved := 6
			for i := 0; i < largestObserved; i++ {
				if i == 2 || i == 3 { // skip Packet 3 and 4
					continue
				}
				entropy.Add(packets[i].PacketNumber, packets[i].EntropyBit)
			}
			handler.ackPacket(1)
			handler.ackPacket(2)
			handler.ackPacket(5)
			ack := frames.AckFrame{
				LargestObserved: protocol.PacketNumber(largestObserved),
				NackRanges:      []frames.NackRange{frames.NackRange{FirstPacketNumber: 3, LastPacketNumber: 4}},
			}
			calculatedEntropy, err := handler.calculateExpectedEntropy(&ack)
			Expect(err).ToNot(HaveOccurred())
			Expect(calculatedEntropy).To(Equal(entropy))
		})

		It("multiple NACK ranges", func() {
			largestObserved := 5
			for i := 0; i < largestObserved; i++ {
				if i == 1 || i == 3 { // skip Packet 2 and 4
					continue
				}
				entropy.Add(packets[i].PacketNumber, packets[i].EntropyBit)
			}
			ack := frames.AckFrame{
				LargestObserved: protocol.PacketNumber(largestObserved),
				NackRanges: []frames.NackRange{
					frames.NackRange{FirstPacketNumber: 4, LastPacketNumber: 4},
					frames.NackRange{FirstPacketNumber: 2, LastPacketNumber: 2},
				},
			}
			calculatedEntropy, err := handler.calculateExpectedEntropy(&ack)
			Expect(err).ToNot(HaveOccurred())
			Expect(calculatedEntropy).To(Equal(entropy))
		})

		It("actually rejects an ACK with the wrong entropy", func() {
			ack := frames.AckFrame{
				LargestObserved: 4,
				Entropy:         1,
			}
			err := handler.ReceivedAck(&ack)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(errEntropy))
		})

		It("completely processes an ACK without a NACK range", func() {
			entropy := EntropyAccumulator(0)
			largestObserved := 4
			for i := 0; i < largestObserved; i++ {
				entropy.Add(packets[i].PacketNumber, packets[i].EntropyBit)
			}
			ack := frames.AckFrame{
				LargestObserved: protocol.PacketNumber(largestObserved),
				Entropy:         byte(entropy),
			}
			err := handler.ReceivedAck(&ack)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.LargestObserved).To(Equal(protocol.PacketNumber(largestObserved)))
			Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(largestObserved)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(largestObserved - 1)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(largestObserved + 1)))
		})

		It("completely processes an ACK with a NACK range", func() {
			entropy := EntropyAccumulator(0)
			largestObserved := 6
			for i := 0; i < largestObserved; i++ {
				if i == 2 || i == 4 { // Packet Number 3 and 5 missing
					continue
				}
				entropy.Add(packets[i].PacketNumber, packets[i].EntropyBit)
			}
			ack := frames.AckFrame{
				LargestObserved: protocol.PacketNumber(largestObserved),
				Entropy:         byte(entropy),
				NackRanges: []frames.NackRange{
					frames.NackRange{FirstPacketNumber: 5, LastPacketNumber: 5},
					frames.NackRange{FirstPacketNumber: 3, LastPacketNumber: 3},
				},
			}
			err := handler.ReceivedAck(&ack)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.LargestObserved).To(Equal(protocol.PacketNumber(largestObserved)))
			Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(3)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(4)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(5)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(6)))
		})
	})

	Context("ACK processing", func() { // in all these tests, the EntropyBit of each Packet is set to false, so that the resulting EntropyByte will always be 0
		var packets []*Packet

		BeforeEach(func() {
			packets = []*Packet{
				&Packet{PacketNumber: 1, Plaintext: []byte{0x13, 0x37}, EntropyBit: false},
				&Packet{PacketNumber: 2, Plaintext: []byte{0xBE, 0xEF}, EntropyBit: false},
				&Packet{PacketNumber: 3, Plaintext: []byte{0xCA, 0xFE}, EntropyBit: false},
				&Packet{PacketNumber: 4, Plaintext: []byte{0x54, 0x32}, EntropyBit: false},
				&Packet{PacketNumber: 5, Plaintext: []byte{0x54, 0x32}, EntropyBit: false},
				&Packet{PacketNumber: 6, Plaintext: []byte{0x54, 0x32}, EntropyBit: false},
			}
			for _, packet := range packets {
				handler.SentPacket(packet)
			}
		})

		Context("ACK validation", func() {
			It("rejects duplicate ACKs", func() {
				largestObserved := 3
				ack := frames.AckFrame{
					LargestObserved: protocol.PacketNumber(largestObserved),
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedAck(&ack)
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(errDuplicateOrOutOfOrderAck))
			})

			It("rejects out of order ACKs", func() {
				largestObserved := 3
				ack := frames.AckFrame{
					LargestObserved: protocol.PacketNumber(largestObserved),
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				ack.LargestObserved--
				err = handler.ReceivedAck(&ack)
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(errDuplicateOrOutOfOrderAck))
				Expect(handler.LargestObserved).To(Equal(protocol.PacketNumber(largestObserved)))
			})

			It("rejects ACKs with a too high LargestObserved packet number", func() {
				ack := frames.AckFrame{
					LargestObserved: packets[len(packets)-1].PacketNumber + 1337,
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(errAckForUnsentPacket))
				Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(0)))
			})
		})
	})

	Context("Retransmission handler", func() {
		var packets []*Packet

		BeforeEach(func() {
			retransmissionThreshold = 1

			packets = []*Packet{
				&Packet{PacketNumber: 1, Plaintext: []byte{0x13, 0x37}, EntropyBit: false},
				&Packet{PacketNumber: 2, Plaintext: []byte{0xBE, 0xEF}, EntropyBit: false},
				&Packet{PacketNumber: 3, Plaintext: []byte{0xCA, 0xFE}, EntropyBit: false},
				&Packet{PacketNumber: 4, Plaintext: []byte{0x54, 0x32}, EntropyBit: false},
				&Packet{PacketNumber: 5, Plaintext: []byte{0x12, 0x42}, EntropyBit: false},
				&Packet{PacketNumber: 6, Plaintext: []byte{0xCA, 0xFE}, EntropyBit: false},
			}
			for _, packet := range packets {
				handler.SentPacket(packet)
			}
		})

		It("queues a packet for retransmission", func() {
			handler.nackPacket(2)
			handler.nackPacket(2)
			Expect(len(handler.retransmissionQueue)).To(Equal(1))
			Expect(handler.retransmissionQueue[0].PacketNumber).To(Equal(protocol.PacketNumber(2)))
		})

		It("dequeues a packet for retransmission", func() {
			handler.nackPacket(3)
			handler.nackPacket(3)
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("keeps the packets in the right order", func() {
			handler.nackPacket(2)
			handler.nackPacket(2)
			handler.nackPacket(4)
			handler.nackPacket(4)
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(2)))
			packet = handler.DequeuePacketForRetransmission()
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(4)))
		})

		It("only queues each packet once, regardless of the number of NACKs", func() {
			handler.nackPacket(2)
			handler.nackPacket(2)
			handler.nackPacket(4)
			handler.nackPacket(4)
			handler.nackPacket(2)
			handler.nackPacket(2)
			_ = handler.DequeuePacketForRetransmission()
			_ = handler.DequeuePacketForRetransmission()
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("recalculates the highestInOrderAckedPacketNumber after queueing a retransmission", func() {
			ack := frames.AckFrame{
				LargestObserved: 4,
				NackRanges:      []frames.NackRange{frames.NackRange{FirstPacketNumber: 3, LastPacketNumber: 3}},
			}
			err := handler.ReceivedAck(&ack)
			Expect(err).ToNot(HaveOccurred())
			handler.nackPacket(3) // this is the second NACK for this packet
			Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(4)))
		})
	})
})
