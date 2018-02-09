package ackhandler

import (
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func retransmittablePacket(num protocol.PacketNumber) *Packet {
	return &Packet{
		PacketNumber:    num,
		Length:          1,
		Frames:          []wire.Frame{&wire.PingFrame{}},
		EncryptionLevel: protocol.EncryptionForwardSecure,
	}
}

func nonRetransmittablePacket(num protocol.PacketNumber) *Packet {
	return &Packet{PacketNumber: num, Length: 1, Frames: []wire.Frame{&wire.AckFrame{}}}
}

func handshakePacket(num protocol.PacketNumber) *Packet {
	return &Packet{
		PacketNumber:    num,
		Length:          1,
		Frames:          []wire.Frame{&wire.PingFrame{}},
		EncryptionLevel: protocol.EncryptionUnencrypted,
	}
}

var _ = Describe("SentPacketHandler", func() {
	var (
		handler     *sentPacketHandler
		streamFrame wire.StreamFrame
	)

	BeforeEach(func() {
		rttStats := &congestion.RTTStats{}
		handler = NewSentPacketHandler(rttStats).(*sentPacketHandler)
		handler.SetHandshakeComplete()
		streamFrame = wire.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}
	})

	getPacketElement := func(p protocol.PacketNumber) *PacketElement {
		for el := handler.packetHistory.Front(); el != nil; el = el.Next() {
			if el.Value.PacketNumber == p {
				return el
			}
		}
		return nil
	}

	It("gets the LeastUnacked packet number", func() {
		handler.largestAcked = 0x1337
		Expect(handler.GetLeastUnacked()).To(Equal(protocol.PacketNumber(0x1337 + 1)))
	})

	Context("registering sent packets", func() {
		It("accepts two consecutive packets", func() {
			packet1 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
			packet2 := Packet{PacketNumber: 2, Frames: []wire.Frame{&streamFrame}, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.packetHistory.Back().Value.PacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(3)))
			Expect(handler.skippedPackets).To(BeEmpty())
		})

		It("accepts packet number 0", func() {
			packet1 := Packet{PacketNumber: 0, Frames: []wire.Frame{&streamFrame}, Length: 1}
			packet2 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.lastSentPacketNumber).To(BeZero())
			err = handler.SentPacket(&packet2)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(0)))
			Expect(handler.packetHistory.Back().Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(3)))
			Expect(handler.skippedPackets).To(BeEmpty())
		})

		It("stores the sent time", func() {
			packet := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
			err := handler.SentPacket(&packet)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory.Front().Value.sendTime.Unix()).To(BeNumerically("~", time.Now().Unix(), 1))
		})

		It("does not store non-retransmittable packets", func() {
			err := handler.SentPacket(&Packet{PacketNumber: 1, Length: 1})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory.Len()).To(BeZero())
		})

		Context("skipped packet numbers", func() {
			It("works with non-consecutive packet numbers", func() {
				packet1 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
				packet2 := Packet{PacketNumber: 3, Frames: []wire.Frame{&streamFrame}, Length: 2}
				err := handler.SentPacket(&packet1)
				Expect(err).ToNot(HaveOccurred())
				err = handler.SentPacket(&packet2)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(3)))
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(3)))
				Expect(handler.skippedPackets).To(HaveLen(1))
				Expect(handler.skippedPackets[0]).To(Equal(protocol.PacketNumber(2)))
			})

			It("recognizes multiple skipped packets", func() {
				packet1 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
				packet2 := Packet{PacketNumber: 3, Frames: []wire.Frame{&streamFrame}, Length: 2}
				packet3 := Packet{PacketNumber: 5, Frames: []wire.Frame{&streamFrame}, Length: 2}
				err := handler.SentPacket(&packet1)
				Expect(err).ToNot(HaveOccurred())
				err = handler.SentPacket(&packet2)
				Expect(err).ToNot(HaveOccurred())
				err = handler.SentPacket(&packet3)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.skippedPackets).To(HaveLen(2))
				Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2, 4}))
			})

			It("recognizes multiple consecutive skipped packets", func() {
				packet1 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
				packet2 := Packet{PacketNumber: 4, Frames: []wire.Frame{&streamFrame}, Length: 2}
				err := handler.SentPacket(&packet1)
				Expect(err).ToNot(HaveOccurred())
				err = handler.SentPacket(&packet2)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.skippedPackets).To(HaveLen(2))
				Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2, 3}))
			})

			It("limits the lengths of the skipped packet slice", func() {
				for i := 0; i < protocol.MaxTrackedSkippedPackets+5; i++ {
					packet := Packet{PacketNumber: protocol.PacketNumber(2*i + 1), Frames: []wire.Frame{&streamFrame}, Length: 1}
					err := handler.SentPacket(&packet)
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(handler.skippedPackets).To(HaveLen(protocol.MaxUndecryptablePackets))
				Expect(handler.skippedPackets[0]).To(Equal(protocol.PacketNumber(10)))
				Expect(handler.skippedPackets[protocol.MaxTrackedSkippedPackets-1]).To(Equal(protocol.PacketNumber(10 + 2*(protocol.MaxTrackedSkippedPackets-1))))
			})

			Context("garbage collection", func() {
				It("keeps all packet numbers above the LargestAcked", func() {
					handler.skippedPackets = []protocol.PacketNumber{2, 5, 8, 10}
					handler.largestAcked = 1
					handler.garbageCollectSkippedPackets()
					Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2, 5, 8, 10}))
				})

				It("doesn't keep packet numbers below the LargestAcked", func() {
					handler.skippedPackets = []protocol.PacketNumber{1, 5, 8, 10}
					handler.largestAcked = 5
					handler.garbageCollectSkippedPackets()
					Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{8, 10}))
				})

				It("deletes all packet numbers if LargestAcked is sufficiently high", func() {
					handler.skippedPackets = []protocol.PacketNumber{1, 5, 10}
					handler.largestAcked = 15
					handler.garbageCollectSkippedPackets()
					Expect(handler.skippedPackets).To(BeEmpty())
				})
			})
		})
	})

	Context("DoS mitigation", func() {
		It("checks the size of the packet history, for unacked packets", func() {
			i := protocol.PacketNumber(1)
			for ; i <= protocol.MaxTrackedSentPackets; i++ {
				err := handler.SentPacket(retransmittablePacket(i))
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.SentPacket(retransmittablePacket(i))
			Expect(err).To(MatchError("Too many outstanding non-acked and non-retransmitted packets"))
		})

		// TODO: add a test that the length of the retransmission queue is considered, even if packets have already been ACKed. Relevant once we drop support for QUIC 33 and earlier
	})

	Context("ACK processing", func() {
		var packets []*Packet

		BeforeEach(func() {
			packets = []*Packet{
				{PacketNumber: 0, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 2, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 3, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 4, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 5, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 6, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 7, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 8, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 9, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 10, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 12, Frames: []wire.Frame{&streamFrame}, Length: 1},
			}
			for _, packet := range packets {
				err := handler.SentPacket(packet)
				Expect(err).NotTo(HaveOccurred())
			}
			// Increase RTT, because the tests would be flaky otherwise
			handler.rttStats.UpdateRTT(time.Hour, 0, time.Now())
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets))))
		})

		expectInPacketHistory := func(expected []protocol.PacketNumber) {
			var packets []protocol.PacketNumber
			for el := handler.packetHistory.Front(); el != nil; el = el.Next() {
				packets = append(packets, el.Value.PacketNumber)
			}
			ExpectWithOffset(1, packets).To(Equal(expected))
		}

		Context("ACK validation", func() {
			It("rejects duplicate ACKs", func() {
				largestAcked := 3
				ack := wire.AckFrame{
					LargestAcked: protocol.PacketNumber(largestAcked),
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack, 1337, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).To(MatchError(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects out of order ACKs", func() {
				// acks packets 0, 1, 2, 3
				ack := wire.AckFrame{LargestAcked: 3}
				err := handler.ReceivedAck(&ack, 1337, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 4)))
				err = handler.ReceivedAck(&ack, 1337-1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).To(MatchError(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.largestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 4)))
			})

			It("rejects ACKs with a too high LargestAcked packet number", func() {
				ack := wire.AckFrame{
					LargestAcked: packets[len(packets)-1].PacketNumber + 1337,
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).To(MatchError("InvalidAckData: Received ACK for an unsent package"))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets))))
			})

			It("ignores repeated ACKs", func() {
				ack := wire.AckFrame{
					LargestAcked: 3,
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack, 1337, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337+1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.largestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects ACKs for skipped packets", func() {
				ack := wire.AckFrame{
					LargestAcked: 12,
					LowestAcked:  5,
				}
				err := handler.ReceivedAck(&ack, 1337, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).To(MatchError("InvalidAckData: Received an ACK for a skipped packet number"))
			})

			It("accepts an ACK that correctly nacks a skipped packet", func() {
				ack := wire.AckFrame{
					LargestAcked: 12,
					LowestAcked:  5,
					AckRanges: []wire.AckRange{
						{First: 12, Last: 12},
						{First: 5, Last: 10},
					},
				}
				err := handler.ReceivedAck(&ack, 1337, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.largestAcked).ToNot(BeZero())
			})
		})

		Context("acks and nacks the right packets", func() {
			It("adjusts the LargestAcked", func() {
				ack := wire.AckFrame{
					LargestAcked: 5,
					LowestAcked:  0,
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.largestAcked).To(Equal(protocol.PacketNumber(5)))
				el := handler.packetHistory.Front()
				for i := 6; i <= 10; i++ {
					Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(i)))
					el = el.Next()
				}
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(12)))
			})

			It("rejects an ACK that acks packets with a higher encryption level", func() {
				err := handler.SentPacket(&Packet{
					PacketNumber:    13,
					EncryptionLevel: protocol.EncryptionForwardSecure,
					Frames:          []wire.Frame{&streamFrame},
					Length:          1,
				})
				ack := wire.AckFrame{
					LargestAcked: 13,
					LowestAcked:  13,
				}
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedAck(&ack, 1, protocol.EncryptionSecure, time.Now())
				Expect(err).To(MatchError("Received ACK with encryption level encrypted (not forward-secure) that acks a packet 13 (encryption level forward-secure)"))
			})

			It("acks all packets for an ACK frame with no missing packets", func() {
				ack := wire.AckFrame{
					LargestAcked: 8,
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(0)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(9)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(10)))
				Expect(el.Next().Value.PacketNumber).To(Equal(protocol.PacketNumber(12)))
			})

			It("acks packet 0", func() {
				ack := wire.AckFrame{
					LargestAcked: 0,
					LowestAcked:  0,
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12})
			})

			It("handles an ACK frame with one missing packet range", func() {
				ack := wire.AckFrame{
					LargestAcked: 9,
					LowestAcked:  1,
					AckRanges: []wire.AckRange{ // packets 4 and 5 were lost
						{First: 6, Last: 9},
						{First: 1, Last: 3},
					},
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{0, 4, 5, 10, 12})
			})

			It("does not ack packets below the LowestAcked", func() {
				ack := wire.AckFrame{
					LargestAcked: 8,
					LowestAcked:  3,
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{0, 1, 2, 9, 10, 12})
			})

			It("handles an ACK with multiple missing packet ranges", func() {
				ack := wire.AckFrame{
					LargestAcked: 9,
					LowestAcked:  1,
					AckRanges: []wire.AckRange{ // packets 2, 4 and 5, and 8 were lost
						{First: 9, Last: 9},
						{First: 6, Last: 7},
						{First: 3, Last: 3},
						{First: 1, Last: 1},
					},
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{0, 2, 4, 5, 8, 10, 12})
			})

			It("processes an ACK frame that would be sent after a late arrival of a packet", func() {
				largestObserved := 6
				ack1 := wire.AckFrame{
					LargestAcked: protocol.PacketNumber(largestObserved),
					LowestAcked:  1,
					AckRanges: []wire.AckRange{
						{First: 4, Last: protocol.PacketNumber(largestObserved)},
						{First: 1, Last: 2},
					},
				}
				err := handler.ReceivedAck(&ack1, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 5)))
				expectInPacketHistory([]protocol.PacketNumber{0, 3, 7, 8, 9, 10, 12})
				ack2 := wire.AckFrame{
					LargestAcked: protocol.PacketNumber(largestObserved),
					LowestAcked:  1,
				}
				err = handler.ReceivedAck(&ack2, 2, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 6)))
				expectInPacketHistory([]protocol.PacketNumber{0, 7, 8, 9, 10, 12})
			})

			It("processes an ACK frame that would be sent after a late arrival of a packet and another packet", func() {
				ack1 := wire.AckFrame{
					LargestAcked: 6,
					LowestAcked:  0,
					AckRanges: []wire.AckRange{
						{First: 4, Last: 6},
						{First: 0, Last: 2},
					},
				}
				err := handler.ReceivedAck(&ack1, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 6)))
				expectInPacketHistory([]protocol.PacketNumber{3, 7, 8, 9, 10, 12})
				ack2 := wire.AckFrame{
					LargestAcked: 7,
					LowestAcked:  1,
				}
				err = handler.ReceivedAck(&ack2, 2, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 8)))
				expectInPacketHistory([]protocol.PacketNumber{8, 9, 10, 12})
			})

			It("processes an ACK that contains old ACK ranges", func() {
				ack1 := wire.AckFrame{
					LargestAcked: 6,
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack1, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{0, 7, 8, 9, 10, 12})
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 6)))
				ack2 := wire.AckFrame{
					LargestAcked: 10,
					LowestAcked:  1,
					AckRanges: []wire.AckRange{
						{First: 8, Last: 10},
						{First: 3, Last: 3},
						{First: 1, Last: 1},
					},
				}
				err = handler.ReceivedAck(&ack2, 2, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 6 - 3)))
				expectInPacketHistory([]protocol.PacketNumber{0, 7, 12})
			})
		})

		Context("calculating RTT", func() {
			It("computes the RTT", func() {
				now := time.Now()
				// First, fake the sent times of the first, second and last packet
				getPacketElement(1).Value.sendTime = now.Add(-10 * time.Minute)
				getPacketElement(2).Value.sendTime = now.Add(-5 * time.Minute)
				getPacketElement(6).Value.sendTime = now.Add(-1 * time.Minute)
				// Now, check that the proper times are used when calculating the deltas
				err := handler.ReceivedAck(&wire.AckFrame{LargestAcked: 1}, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 10*time.Minute, 1*time.Second))
				err = handler.ReceivedAck(&wire.AckFrame{LargestAcked: 2}, 2, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
				err = handler.ReceivedAck(&wire.AckFrame{LargestAcked: 6}, 3, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 1*time.Minute, 1*time.Second))
			})

			It("uses the DelayTime in the ACK frame", func() {
				now := time.Now()
				// make sure the rttStats have a min RTT, so that the delay is used
				handler.rttStats.UpdateRTT(5*time.Minute, 0, time.Now())
				getPacketElement(1).Value.sendTime = now.Add(-10 * time.Minute)
				err := handler.ReceivedAck(&wire.AckFrame{LargestAcked: 1, DelayTime: 5 * time.Minute}, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
			})
		})

		Context("determinining, which ACKs we have received an ACK for", func() {
			BeforeEach(func() {
				morePackets := []*Packet{
					&Packet{PacketNumber: 13, Frames: []wire.Frame{&wire.AckFrame{LowestAcked: 80, LargestAcked: 100}, &streamFrame}, Length: 1},
					&Packet{PacketNumber: 14, Frames: []wire.Frame{&wire.AckFrame{LowestAcked: 50, LargestAcked: 200}, &streamFrame}, Length: 1},
					&Packet{PacketNumber: 15, Frames: []wire.Frame{&streamFrame}, Length: 1},
				}
				for _, packet := range morePackets {
					err := handler.SentPacket(packet)
					Expect(err).NotTo(HaveOccurred())
				}
			})

			It("determines which ACK we have received an ACK for", func() {
				err := handler.ReceivedAck(&wire.AckFrame{LargestAcked: 15, LowestAcked: 12}, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(201)))
			})

			It("doesn't do anything when the acked packet didn't contain an ACK", func() {
				err := handler.ReceivedAck(&wire.AckFrame{LargestAcked: 13, LowestAcked: 13}, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(101)))
				err = handler.ReceivedAck(&wire.AckFrame{LargestAcked: 15, LowestAcked: 15}, 2, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(101)))
			})

			It("doesn't decrease the value", func() {
				err := handler.ReceivedAck(&wire.AckFrame{LargestAcked: 14, LowestAcked: 14}, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(201)))
				err = handler.ReceivedAck(&wire.AckFrame{LargestAcked: 13, LowestAcked: 13}, 2, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(201)))
			})
		})
	})

	Context("Retransmission handling", func() {
		var packets []*Packet

		BeforeEach(func() {
			packets = []*Packet{
				{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1, EncryptionLevel: protocol.EncryptionUnencrypted},
				{PacketNumber: 2, Frames: []wire.Frame{&streamFrame}, Length: 1, EncryptionLevel: protocol.EncryptionUnencrypted},
				{PacketNumber: 3, Frames: []wire.Frame{&streamFrame}, Length: 1, EncryptionLevel: protocol.EncryptionUnencrypted},
				{PacketNumber: 4, Frames: []wire.Frame{&streamFrame}, Length: 1, EncryptionLevel: protocol.EncryptionSecure},
				{PacketNumber: 5, Frames: []wire.Frame{&streamFrame}, Length: 1, EncryptionLevel: protocol.EncryptionSecure},
				{PacketNumber: 6, Frames: []wire.Frame{&streamFrame}, Length: 1, EncryptionLevel: protocol.EncryptionForwardSecure},
				{PacketNumber: 7, Frames: []wire.Frame{&streamFrame}, Length: 1, EncryptionLevel: protocol.EncryptionForwardSecure},
			}
			for _, packet := range packets {
				handler.SentPacket(packet)
			}
			// Increase RTT, because the tests would be flaky otherwise
			handler.rttStats.UpdateRTT(time.Minute, 0, time.Now())
			// Ack a single packet so that we have non-RTO timings
			handler.ReceivedAck(&wire.AckFrame{LargestAcked: 2, LowestAcked: 2}, 1, protocol.EncryptionForwardSecure, time.Now())
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(6)))
		})

		It("does not dequeue a packet if no ack has been received", func() {
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("dequeues a packet for retransmission", func() {
			getPacketElement(1).Value.sendTime = time.Now().Add(-time.Hour)
			handler.OnAlarm()
			Expect(getPacketElement(1)).To(BeNil())
			Expect(handler.retransmissionQueue).To(HaveLen(1))
			Expect(handler.retransmissionQueue[0].PacketNumber).To(Equal(protocol.PacketNumber(1)))
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("deletes non forward-secure packets when the handshake completes", func() {
			for i := protocol.PacketNumber(1); i <= 7; i++ {
				if i == 2 { // packet 2 was already acked in BeforeEach
					continue
				}
				handler.queuePacketForRetransmission(getPacketElement(i))
			}
			Expect(handler.retransmissionQueue).To(HaveLen(6))
			handler.SetHandshakeComplete()
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(6)))
			packet = handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(7)))
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		Context("STOP_WAITINGs", func() {
			It("gets a STOP_WAITING frame", func() {
				ack := wire.AckFrame{LargestAcked: 5, LowestAcked: 5}
				err := handler.ReceivedAck(&ack, 2, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetStopWaitingFrame(false)).To(Equal(&wire.StopWaitingFrame{LeastUnacked: 6}))
			})

			It("gets a STOP_WAITING frame after queueing a retransmission", func() {
				handler.queuePacketForRetransmission(getPacketElement(5))
				Expect(handler.GetStopWaitingFrame(false)).To(Equal(&wire.StopWaitingFrame{LeastUnacked: 6}))
			})
		})
	})

	It("calculates bytes in flight", func() {
		packet1 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
		packet2 := Packet{PacketNumber: 2, Frames: []wire.Frame{&streamFrame}, Length: 2}
		packet3 := Packet{PacketNumber: 3, Frames: []wire.Frame{&streamFrame}, Length: 3}
		err := handler.SentPacket(&packet1)
		Expect(err).NotTo(HaveOccurred())
		Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(1)))
		err = handler.SentPacket(&packet2)
		Expect(err).NotTo(HaveOccurred())
		Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(1 + 2)))
		err = handler.SentPacket(&packet3)
		Expect(err).NotTo(HaveOccurred())
		Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(1 + 2 + 3)))

		// Increase RTT, because the tests would be flaky otherwise
		handler.rttStats.UpdateRTT(time.Minute, 0, time.Now())

		// ACK 1 and 3, NACK 2
		ack := wire.AckFrame{
			LargestAcked: 3,
			LowestAcked:  1,
			AckRanges: []wire.AckRange{
				{First: 3, Last: 3},
				{First: 1, Last: 1},
			},
		}
		err = handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
		Expect(err).NotTo(HaveOccurred())
		Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))

		handler.packetHistory.Front().Value.sendTime = time.Now().Add(-time.Hour)
		handler.OnAlarm()

		Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(0)))
	})

	Context("congestion", func() {
		var cong *mocks.MockSendAlgorithm

		BeforeEach(func() {
			cong = mocks.NewMockSendAlgorithm(mockCtrl)
			cong.EXPECT().RetransmissionDelay().AnyTimes()
			handler.congestion = cong
		})

		It("should call OnSent", func() {
			cong.EXPECT().OnPacketSent(
				gomock.Any(),
				protocol.ByteCount(42),
				protocol.PacketNumber(1),
				protocol.ByteCount(42),
				true,
			)
			cong.EXPECT().TimeUntilSend(gomock.Any())
			p := &Packet{
				PacketNumber: 1,
				Length:       42,
				Frames:       []wire.Frame{&wire.PingFrame{}},
			}
			err := handler.SentPacket(p)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should call MaybeExitSlowStart and OnPacketAcked", func() {
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
			cong.EXPECT().TimeUntilSend(gomock.Any()).Times(2)
			cong.EXPECT().MaybeExitSlowStart()
			cong.EXPECT().OnPacketAcked(
				protocol.PacketNumber(1),
				protocol.ByteCount(1),
				protocol.ByteCount(1),
			)
			handler.SentPacket(retransmittablePacket(1))
			handler.SentPacket(retransmittablePacket(2))
			err := handler.ReceivedAck(&wire.AckFrame{LargestAcked: 1, LowestAcked: 1}, 1, protocol.EncryptionForwardSecure, time.Now())
			Expect(err).NotTo(HaveOccurred())
		})

		It("should call MaybeExitSlowStart and OnPacketLost", func() {
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3)
			cong.EXPECT().TimeUntilSend(gomock.Any()).Times(3)
			cong.EXPECT().OnRetransmissionTimeout(true).Times(2)
			cong.EXPECT().OnPacketLost(
				protocol.PacketNumber(1),
				protocol.ByteCount(1),
				protocol.ByteCount(2),
			)
			cong.EXPECT().OnPacketLost(
				protocol.PacketNumber(2),
				protocol.ByteCount(1),
				protocol.ByteCount(1),
			)
			handler.SentPacket(retransmittablePacket(1))
			handler.SentPacket(retransmittablePacket(2))
			handler.SentPacket(retransmittablePacket(3))
			handler.OnAlarm() // RTO, meaning 2 lost packets
		})

		It("allows or denies sending based on congestion", func() {
			handler.bytesInFlight = 100
			cong.EXPECT().GetCongestionWindow().Return(protocol.ByteCount(200))
			Expect(handler.SendingAllowed()).To(BeTrue())
			cong.EXPECT().GetCongestionWindow().Return(protocol.ByteCount(75))
			Expect(handler.SendingAllowed()).To(BeFalse())
		})

		It("allows or denies sending based on the number of tracked packets", func() {
			cong.EXPECT().GetCongestionWindow().Times(2)
			Expect(handler.SendingAllowed()).To(BeTrue())
			handler.retransmissionQueue = make([]*Packet, protocol.MaxTrackedSentPackets)
			Expect(handler.SendingAllowed()).To(BeFalse())
		})

		It("allows sending if there are retransmisisons outstanding", func() {
			cong.EXPECT().GetCongestionWindow().Times(2)
			handler.bytesInFlight = 100
			Expect(handler.retransmissionQueue).To(BeEmpty())
			Expect(handler.SendingAllowed()).To(BeFalse())
			handler.retransmissionQueue = []*Packet{{PacketNumber: 3}}
			Expect(handler.SendingAllowed()).To(BeTrue())
		})

		It("gets the pacing delay", func() {
			handler.bytesInFlight = 100
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			cong.EXPECT().TimeUntilSend(protocol.ByteCount(100)).Return(time.Hour)
			handler.SentPacket(&Packet{PacketNumber: 1})
			Expect(handler.TimeUntilSend()).To(BeTemporally("~", time.Now().Add(time.Hour), time.Second))
		})

		It("allows sending of one packet, if it should be sent immediately", func() {
			cong.EXPECT().TimeUntilSend(gomock.Any()).Return(time.Duration(0))
			Expect(handler.ShouldSendNumPackets()).To(Equal(1))
		})

		It("allows sending of multiple packets, if the pacing delay is smaller than the minimum", func() {
			pacingDelay := protocol.MinPacingDelay / 10
			cong.EXPECT().TimeUntilSend(gomock.Any()).Return(pacingDelay)
			Expect(handler.ShouldSendNumPackets()).To(Equal(10))
		})

		It("allows sending of multiple packets, if the pacing delay is smaller than the minimum, and not a fraction", func() {
			pacingDelay := protocol.MinPacingDelay * 2 / 5
			cong.EXPECT().TimeUntilSend(gomock.Any()).Return(pacingDelay)
			Expect(handler.ShouldSendNumPackets()).To(Equal(3))
		})
	})

	Context("calculating RTO", func() {
		It("uses default RTO", func() {
			Expect(handler.computeRTOTimeout()).To(Equal(defaultRTOTimeout))
		})

		It("uses RTO from rttStats", func() {
			rtt := time.Second
			expected := rtt + rtt/2*4
			handler.rttStats.UpdateRTT(rtt, 0, time.Now())
			Expect(handler.computeRTOTimeout()).To(Equal(expected))
		})

		It("limits RTO min", func() {
			rtt := time.Millisecond
			handler.rttStats.UpdateRTT(rtt, 0, time.Now())
			Expect(handler.computeRTOTimeout()).To(Equal(minRTOTimeout))
		})

		It("limits RTO max", func() {
			rtt := time.Hour
			handler.rttStats.UpdateRTT(rtt, 0, time.Now())
			Expect(handler.computeRTOTimeout()).To(Equal(maxRTOTimeout))
		})

		It("implements exponential backoff", func() {
			handler.rtoCount = 0
			Expect(handler.computeRTOTimeout()).To(Equal(defaultRTOTimeout))
			handler.rtoCount = 1
			Expect(handler.computeRTOTimeout()).To(Equal(2 * defaultRTOTimeout))
			handler.rtoCount = 2
			Expect(handler.computeRTOTimeout()).To(Equal(4 * defaultRTOTimeout))
		})
	})

	Context("Delay-based loss detection", func() {
		It("detects a packet as lost", func() {
			err := handler.SentPacket(retransmittablePacket(1))
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(retransmittablePacket(2))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeTrue())

			err = handler.ReceivedAck(&wire.AckFrame{LargestAcked: 2, LowestAcked: 2}, 1, protocol.EncryptionForwardSecure, time.Now().Add(time.Hour))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeFalse())

			// RTT is around 1h now.
			// The formula is (1+1/8) * RTT, so this should be around that number
			Expect(handler.lossTime.Sub(time.Now())).To(BeNumerically("~", time.Hour*9/8, time.Minute))
			Expect(handler.GetAlarmTimeout().Sub(time.Now())).To(BeNumerically("~", time.Hour*9/8, time.Minute))

			handler.packetHistory.Front().Value.sendTime = time.Now().Add(-2 * time.Hour)
			handler.OnAlarm()
			Expect(handler.DequeuePacketForRetransmission()).NotTo(BeNil())
		})

		It("does not detect packets as lost without ACKs", func() {
			err := handler.SentPacket(&Packet{PacketNumber: 1, Length: 1})
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(retransmittablePacket(2))
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(retransmittablePacket(3))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeTrue())

			err = handler.ReceivedAck(&wire.AckFrame{LargestAcked: 1, LowestAcked: 1}, 1, protocol.EncryptionUnencrypted, time.Now().Add(time.Hour))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeTrue())
			Expect(handler.GetAlarmTimeout().Sub(time.Now())).To(BeNumerically("~", handler.computeRTOTimeout(), time.Minute))

			// This means RTO, so both packets should be lost
			handler.OnAlarm()
			Expect(handler.DequeuePacketForRetransmission()).ToNot(BeNil())
			Expect(handler.DequeuePacketForRetransmission()).ToNot(BeNil())
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})
	})

	Context("retransmission for handshake packets", func() {
		BeforeEach(func() {
			handler.handshakeComplete = false
		})

		It("detects the handshake timeout", func() {
			// send handshake packets: 1, 2, 4
			// send a forward-secure packet: 3
			err := handler.SentPacket(handshakePacket(1))
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(handshakePacket(2))
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(retransmittablePacket(3))
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(handshakePacket(4))
			Expect(err).ToNot(HaveOccurred())

			err = handler.ReceivedAck(&wire.AckFrame{LargestAcked: 1, LowestAcked: 1}, 1, protocol.EncryptionSecure, time.Now())
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeTrue())
			handshakeTimeout := handler.computeHandshakeTimeout()
			Expect(handler.GetAlarmTimeout().Sub(time.Now())).To(BeNumerically("~", handshakeTimeout, time.Minute))

			handler.OnAlarm()
			p := handler.DequeuePacketForRetransmission()
			Expect(p).ToNot(BeNil())
			Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(2)))
			p = handler.DequeuePacketForRetransmission()
			Expect(p).ToNot(BeNil())
			Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(4)))
			Expect(handler.packetHistory.Len()).To(Equal(1))
			Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(handler.handshakeCount).To(BeEquivalentTo(1))
			// make sure the exponential backoff is used
			Expect(handler.computeHandshakeTimeout()).To(BeNumerically("~", 2*handshakeTimeout, time.Minute))
		})
	})

	Context("RTO retransmission", func() {
		It("queues two packets if RTO expires", func() {
			err := handler.SentPacket(retransmittablePacket(1))
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(retransmittablePacket(2))
			Expect(err).NotTo(HaveOccurred())

			handler.rttStats.UpdateRTT(time.Hour, 0, time.Now())
			Expect(handler.lossTime.IsZero()).To(BeTrue())
			Expect(handler.GetAlarmTimeout().Sub(time.Now())).To(BeNumerically("~", handler.computeRTOTimeout(), time.Minute))

			handler.OnAlarm()
			p := handler.DequeuePacketForRetransmission()
			Expect(p).ToNot(BeNil())
			Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			p = handler.DequeuePacketForRetransmission()
			Expect(p).ToNot(BeNil())
			Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(2)))

			Expect(handler.rtoCount).To(BeEquivalentTo(1))
		})
	})
})
