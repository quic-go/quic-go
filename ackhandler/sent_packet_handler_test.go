package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SentPacketHandler", func() {
	var handler *sentPacketHandler
	var streamFrame frames.StreamFrame
	BeforeEach(func() {
		stopWaitingManager := NewStopWaitingManager()
		handler = NewSentPacketHandler(stopWaitingManager).(*sentPacketHandler)
		streamFrame = frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}
	})

	BeforeEach(func() {
		retransmissionThreshold = 1
	})

	AfterEach(func() {
		retransmissionThreshold = 3
	})

	Context("SentPacket", func() {
		It("accepts two consecutive packets", func() {
			entropy := EntropyAccumulator(0)
			packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1}
			packet2 := Packet{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 2}
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
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
		})

		It("rejects packets with the same packet number", func() {
			packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1}
			packet2 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).To(HaveOccurred())
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(1)))
		})

		It("rejects non-consecutive packets", func() {
			packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1}
			packet2 := Packet{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).To(HaveOccurred())
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(1)))
		})

		It("correctly calculates the entropy, even if the last packet has already been ACKed", func() {
			packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1}
			packet2 := Packet{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(1)))
			entropy := EntropyAccumulator(0)
			entropy.Add(packet1.PacketNumber, packet1.EntropyBit)
			ack := frames.AckFrame{
				LargestObserved: 1,
				Entropy:         byte(entropy),
			}
			_, _, _, err = handler.ReceivedAck(&ack)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(0)))
			err = handler.SentPacket(&packet2)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(2)))
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(2)))
			entropy.Add(packet2.PacketNumber, packet2.EntropyBit)
			Expect(handler.packetHistory[2].Entropy).To(Equal(entropy))
		})

		It("stores the sent time", func() {
			packet := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1}
			err := handler.SentPacket(&packet)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory[1].sendTime.Unix()).To(BeNumerically("~", time.Now().Unix(), 1))
		})
	})

	Context("ACK entropy calculations", func() {
		var packets []*Packet
		var entropy EntropyAccumulator

		BeforeEach(func() {
			entropy = EntropyAccumulator(0)
			packets = []*Packet{
				&Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1},
				&Packet{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1},
				&Packet{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1},
				&Packet{PacketNumber: 4, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1},
				&Packet{PacketNumber: 5, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1},
				&Packet{PacketNumber: 6, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1},
			}
			for _, packet := range packets {
				handler.SentPacket(packet)
			}
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(6)))
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
			_, _, _, err := handler.ReceivedAck(&ack)
			Expect(err).To(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(6)))
			Expect(err).To(Equal(ErrEntropy))
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
			_, acked, lost, err := handler.ReceivedAck(&ack)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(2)))
			Expect(handler.LargestObserved).To(Equal(protocol.PacketNumber(largestObserved)))
			Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(largestObserved)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(largestObserved - 1)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(largestObserved + 1)))
			Expect(acked).To(HaveLen(4))
			Expect(acked[0].PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(acked[1].PacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(acked[2].PacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(acked[3].PacketNumber).To(Equal(protocol.PacketNumber(4)))
			Expect(lost).To(BeEmpty())
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
			_, acked, lost, err := handler.ReceivedAck(&ack)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(2)))
			Expect(handler.LargestObserved).To(Equal(protocol.PacketNumber(largestObserved)))
			Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(3)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(4)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(5)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(6)))
			Expect(acked).To(HaveLen(4))
			Expect(acked[0].PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(acked[1].PacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(acked[2].PacketNumber).To(Equal(protocol.PacketNumber(6)))
			Expect(acked[3].PacketNumber).To(Equal(protocol.PacketNumber(4)))
			Expect(lost).To(BeEmpty())
		})
	})

	Context("ACK processing", func() { // in all these tests, the EntropyBit of each Packet is set to false, so that the resulting EntropyByte will always be 0
		var packets []*Packet

		BeforeEach(func() {
			packets = []*Packet{
				&Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				&Packet{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				&Packet{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				&Packet{PacketNumber: 4, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				&Packet{PacketNumber: 5, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				&Packet{PacketNumber: 6, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
			}
			for _, packet := range packets {
				handler.SentPacket(packet)
			}
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(6)))
		})

		Context("ACK validation", func() {
			It("rejects duplicate ACKs", func() {
				largestObserved := 3
				ack := frames.AckFrame{
					LargestObserved: protocol.PacketNumber(largestObserved),
				}
				_, _, _, err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
				_, _, _, err = handler.ReceivedAck(&ack)
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
			})

			It("rejects out of order ACKs", func() {
				largestObserved := 3
				ack := frames.AckFrame{
					LargestObserved: protocol.PacketNumber(largestObserved),
				}
				_, _, _, err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
				ack.LargestObserved--
				_, _, _, err = handler.ReceivedAck(&ack)
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.LargestObserved).To(Equal(protocol.PacketNumber(largestObserved)))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
			})

			It("rejects ACKs with a too high LargestObserved packet number", func() {
				ack := frames.AckFrame{
					LargestObserved: packets[len(packets)-1].PacketNumber + 1337,
				}
				_, _, _, err := handler.ReceivedAck(&ack)
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(errAckForUnsentPacket))
				Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(0)))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(6)))
			})
		})

		It("calculates the time delta", func() {
			now := time.Now()
			// First, fake the sent times of the first, second and last packet
			handler.packetHistory[1].sendTime = now.Add(-10 * time.Minute)
			handler.packetHistory[2].sendTime = now.Add(-5 * time.Minute)
			handler.packetHistory[6].sendTime = now.Add(-1 * time.Minute)
			// Now, check that the proper times are used when calculating the deltas
			d, _, _, err := handler.ReceivedAck(&frames.AckFrame{LargestObserved: 1})
			Expect(err).NotTo(HaveOccurred())
			Expect(d).To(BeNumerically("~", 10*time.Minute, 1*time.Second))
			d, _, _, err = handler.ReceivedAck(&frames.AckFrame{LargestObserved: 2})
			Expect(err).NotTo(HaveOccurred())
			Expect(d).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
			d, _, _, err = handler.ReceivedAck(&frames.AckFrame{LargestObserved: 6})
			Expect(err).NotTo(HaveOccurred())
			Expect(d).To(BeNumerically("~", 1*time.Minute, 1*time.Second))
		})
	})

	Context("Retransmission handler", func() {
		var packets []*Packet

		BeforeEach(func() {
			packets = []*Packet{
				&Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				&Packet{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				&Packet{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				&Packet{PacketNumber: 4, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				&Packet{PacketNumber: 5, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				&Packet{PacketNumber: 6, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
			}
			for _, packet := range packets {
				handler.SentPacket(packet)
			}
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(6)))
		})

		It("does not dequeue a packet if no packet has been nacked", func() {
			handler.nackPacket(2)
			Expect(handler.HasPacketForRetransmission()).To(BeFalse())
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("queues a packet for retransmission", func() {
			handler.nackPacket(2)
			handler.nackPacket(2)
			Expect(handler.HasPacketForRetransmission()).To(BeTrue())
			Expect(handler.retransmissionQueue).To(HaveLen(1))
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
			handler.nackPacket(4)
			handler.nackPacket(4)
			handler.nackPacket(2)
			handler.nackPacket(2)
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(2)))
			packet = handler.DequeuePacketForRetransmission()
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(4)))
		})

		It("only queues each packet once, regardless of the number of NACKs", func() {
			handler.nackPacket(4)
			handler.nackPacket(4)
			handler.nackPacket(2)
			handler.nackPacket(2)
			handler.nackPacket(4)
			handler.nackPacket(4)
			_ = handler.DequeuePacketForRetransmission()
			_ = handler.DequeuePacketForRetransmission()
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("does not change the highestInOrderAckedPacketNumber after queueing a retransmission", func() {
			ack := frames.AckFrame{
				LargestObserved: 4,
				NackRanges:      []frames.NackRange{frames.NackRange{FirstPacketNumber: 3, LastPacketNumber: 3}},
			}
			_, _, _, err := handler.ReceivedAck(&ack)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(2)))
			handler.nackPacket(3) // this is the second NACK for this packet
			Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(2)))
		})
	})

	Context("calculating bytes in flight", func() {
		It("works in a typical retransmission scenarios", func() {
			packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1}
			packet2 := Packet{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))

			// ACK 2, NACK 1
			ack := frames.AckFrame{
				LargestObserved: 2,
				NackRanges:      []frames.NackRange{frames.NackRange{FirstPacketNumber: 1, LastPacketNumber: 1}},
			}
			_, _, _, err = handler.ReceivedAck(&ack)
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(1)))

			// Simulate 2 more NACKs
			handler.nackPacket(1)
			handler.nackPacket(1)
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(0)))

			// Retransmission
			packet3 := Packet{PacketNumber: 3, EntropyBit: false, Length: 1}
			err = handler.SentPacket(&packet3)
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(1)))

			// ACK
			ack = frames.AckFrame{
				LargestObserved: 3,
			}
			_, _, _, err = handler.ReceivedAck(&ack)
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(0)))
		})
	})

	It("returns lost packets in ReceivedAck()", func() {
		packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1}
		packet2 := Packet{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 2}
		err := handler.SentPacket(&packet1)
		Expect(err).NotTo(HaveOccurred())
		err = handler.SentPacket(&packet2)
		Expect(err).NotTo(HaveOccurred())

		// First, simulate a NACK for packet number 1
		handler.nackPacket(1)
		// Now, simulate an ack frame
		ack := &frames.AckFrame{
			LargestObserved: 2,
			NackRanges:      []frames.NackRange{frames.NackRange{FirstPacketNumber: 1, LastPacketNumber: 1}},
		}
		_, acked, lost, err := handler.ReceivedAck(ack)
		Expect(err).NotTo(HaveOccurred())
		Expect(acked).To(HaveLen(1))
		Expect(acked[0].PacketNumber).To(Equal(protocol.PacketNumber(2)))
		Expect(lost).To(HaveLen(1))
		Expect(lost[0].PacketNumber).To(Equal(protocol.PacketNumber(1)))
	})
})
