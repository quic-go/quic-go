package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockCongestion struct {
	argsOnPacketSent        []interface{}
	maybeExitSlowStart      bool
	onRetransmissionTimeout bool
	getCongestionWindow     bool
	packetsAcked            [][]interface{}
	packetsLost             [][]interface{}
}

func (m *mockCongestion) TimeUntilSend(now time.Time, bytesInFlight protocol.ByteCount) time.Duration {
	panic("not implemented")
}

func (m *mockCongestion) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) bool {
	m.argsOnPacketSent = []interface{}{sentTime, bytesInFlight, packetNumber, bytes, isRetransmittable}
	return false
}

func (m *mockCongestion) GetCongestionWindow() protocol.ByteCount {
	m.getCongestionWindow = true
	return protocol.DefaultTCPMSS
}

func (m *mockCongestion) MaybeExitSlowStart() {
	m.maybeExitSlowStart = true
}

func (m *mockCongestion) OnRetransmissionTimeout(packetsRetransmitted bool) {
	m.onRetransmissionTimeout = true
}

func (m *mockCongestion) RetransmissionDelay() time.Duration {
	return defaultRTOTimeout
}

func (m *mockCongestion) SetNumEmulatedConnections(n int)         { panic("not implemented") }
func (m *mockCongestion) OnConnectionMigration()                  { panic("not implemented") }
func (m *mockCongestion) SetSlowStartLargeReduction(enabled bool) { panic("not implemented") }

func (m *mockCongestion) OnPacketAcked(n protocol.PacketNumber, l protocol.ByteCount, bif protocol.ByteCount) {
	m.packetsAcked = append(m.packetsAcked, []interface{}{n, l, bif})
}

func (m *mockCongestion) OnPacketLost(n protocol.PacketNumber, l protocol.ByteCount, bif protocol.ByteCount) {
	m.packetsLost = append(m.packetsLost, []interface{}{n, l, bif})
}

var _ = Describe("SentPacketHandler", func() {
	var (
		handler     *sentPacketHandler
		streamFrame frames.StreamFrame
	)

	BeforeEach(func() {
		rttStats := &congestion.RTTStats{}
		handler = NewSentPacketHandler(rttStats).(*sentPacketHandler)
		streamFrame = frames.StreamFrame{
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
		handler.LargestAcked = 0x1337
		Expect(handler.GetLeastUnacked()).To(Equal(protocol.PacketNumber(0x1337 + 1)))
	})

	Context("registering sent packets", func() {
		It("accepts two consecutive packets", func() {
			packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
			packet2 := Packet{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, Length: 2}
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

		It("rejects packets with the same packet number", func() {
			packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
			packet2 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).To(MatchError(errPacketNumberNotIncreasing))
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(1)))
			Expect(handler.skippedPackets).To(BeEmpty())
		})

		It("rejects packets with decreasing packet number", func() {
			packet1 := Packet{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, Length: 1}
			packet2 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).To(MatchError(errPacketNumberNotIncreasing))
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(1)))
		})

		It("stores the sent time", func() {
			packet := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
			err := handler.SentPacket(&packet)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory.Front().Value.SendTime.Unix()).To(BeNumerically("~", time.Now().Unix(), 1))
		})

		Context("skipped packet numbers", func() {
			It("works with non-consecutive packet numbers", func() {
				packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
				packet2 := Packet{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, Length: 2}
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
				packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
				packet2 := Packet{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, Length: 2}
				packet3 := Packet{PacketNumber: 5, Frames: []frames.Frame{&streamFrame}, Length: 2}
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
				packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
				packet2 := Packet{PacketNumber: 4, Frames: []frames.Frame{&streamFrame}, Length: 2}
				err := handler.SentPacket(&packet1)
				Expect(err).ToNot(HaveOccurred())
				err = handler.SentPacket(&packet2)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.skippedPackets).To(HaveLen(2))
				Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2, 3}))
			})

			It("limits the lengths of the skipped packet slice", func() {
				for i := 0; i < protocol.MaxTrackedSkippedPackets+5; i++ {
					packet := Packet{PacketNumber: protocol.PacketNumber(2*i + 1), Frames: []frames.Frame{&streamFrame}, Length: 1}
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
					handler.LargestAcked = 1
					handler.garbageCollectSkippedPackets()
					Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2, 5, 8, 10}))
				})

				It("doesn't keep packet numbers below the LargestAcked", func() {
					handler.skippedPackets = []protocol.PacketNumber{1, 5, 8, 10}
					handler.LargestAcked = 5
					handler.garbageCollectSkippedPackets()
					Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{8, 10}))
				})

				It("deletes all packet numbers if LargestAcked is sufficiently high", func() {
					handler.skippedPackets = []protocol.PacketNumber{1, 5, 10}
					handler.LargestAcked = 15
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
				packet := Packet{PacketNumber: protocol.PacketNumber(i), Length: 1}
				err := handler.SentPacket(&packet)
				Expect(err).ToNot(HaveOccurred())
			}
			packet := Packet{PacketNumber: protocol.PacketNumber(i), Length: 1}
			err := handler.SentPacket(&packet)
			Expect(err).To(MatchError(ErrTooManyTrackedSentPackets))
		})

		// TODO: add a test that the length of the retransmission queue is considered, even if packets have already been ACKed. Relevant once we drop support for QUIC 33 and earlier
	})

	Context("ACK processing", func() {
		var packets []*Packet

		BeforeEach(func() {
			packets = []*Packet{
				{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 4, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 5, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 6, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 7, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 8, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 9, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 10, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 12, Frames: []frames.Frame{&streamFrame}, Length: 1},
			}
			for _, packet := range packets {
				err := handler.SentPacket(packet)
				Expect(err).NotTo(HaveOccurred())
			}
			// Increase RTT, because the tests would be flaky otherwise
			handler.rttStats.UpdateRTT(time.Hour, 0, time.Now())
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets))))
		})

		Context("ACK validation", func() {
			It("rejects duplicate ACKs", func() {
				largestAcked := 3
				ack := frames.AckFrame{
					LargestAcked: protocol.PacketNumber(largestAcked),
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack, 1337, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337, time.Now())
				Expect(err).To(MatchError(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects out of order ACKs", func() {
				ack := frames.AckFrame{
					LargestAcked: 3,
				}
				err := handler.ReceivedAck(&ack, 1337, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337-1, time.Now())
				Expect(err).To(MatchError(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.LargestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects ACKs with a too high LargestAcked packet number", func() {
				ack := frames.AckFrame{
					LargestAcked: packets[len(packets)-1].PacketNumber + 1337,
				}
				err := handler.ReceivedAck(&ack, 1, time.Now())
				Expect(err).To(MatchError(errAckForUnsentPacket))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets))))
			})

			It("ignores repeated ACKs", func() {
				ack := frames.AckFrame{
					LargestAcked: 3,
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack, 1337, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337+1, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.LargestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects ACKs for skipped packets", func() {
				ack := frames.AckFrame{
					LargestAcked: 12,
					LowestAcked:  5,
				}
				err := handler.ReceivedAck(&ack, 1337, time.Now())
				Expect(err).To(MatchError(ErrAckForSkippedPacket))
			})

			It("accepts an ACK that correctly nacks a skipped packet", func() {
				ack := frames.AckFrame{
					LargestAcked: 12,
					LowestAcked:  5,
					AckRanges: []frames.AckRange{
						{FirstPacketNumber: 12, LastPacketNumber: 12},
						{FirstPacketNumber: 5, LastPacketNumber: 10},
					},
				}
				err := handler.ReceivedAck(&ack, 1337, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.LargestAcked).ToNot(BeZero())
			})
		})

		Context("acks and nacks the right packets", func() {
			It("adjusts the LargestAcked", func() {
				ack := frames.AckFrame{
					LargestAcked: 5,
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack, 1, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.LargestAcked).To(Equal(protocol.PacketNumber(5)))
				el := handler.packetHistory.Front()
				for i := 6; i <= 10; i++ {
					Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(i)))
					el = el.Next()
				}
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(12)))
			})

			It("ACKs all packets for an ACK frame with no missing packets", func() {
				ack := frames.AckFrame{
					LargestAcked: 8,
					LowestAcked:  2,
				}
				err := handler.ReceivedAck(&ack, 1, time.Now())
				Expect(err).ToNot(HaveOccurred())
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(9)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(10)))
				Expect(el.Next().Value.PacketNumber).To(Equal(protocol.PacketNumber(12)))
			})

			It("handles an ACK frame with one missing packet range", func() {
				ack := frames.AckFrame{
					LargestAcked: 9,
					LowestAcked:  2,
					AckRanges: []frames.AckRange{ // packets 4 and 5 were lost
						{FirstPacketNumber: 6, LastPacketNumber: 9},
						{FirstPacketNumber: 2, LastPacketNumber: 3},
					},
				}
				err := handler.ReceivedAck(&ack, 1, time.Now())
				Expect(err).ToNot(HaveOccurred())
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(4)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(5)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(10)))
				Expect(el.Next().Value.PacketNumber).To(Equal(protocol.PacketNumber(12)))
			})

			It("Does not ack packets below the LowestAcked", func() {
				ack := frames.AckFrame{
					LargestAcked: 8,
					LowestAcked:  3,
				}
				err := handler.ReceivedAck(&ack, 1, time.Now())
				Expect(err).ToNot(HaveOccurred())
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(2)))
				Expect(el.Next().Value.PacketNumber).To(Equal(protocol.PacketNumber(9)))
			})

			It("handles an ACK with multiple missing packet ranges", func() {
				ack := frames.AckFrame{
					LargestAcked: 9,
					LowestAcked:  1,
					AckRanges: []frames.AckRange{ // packets 2, 4 and 5, and 8 were lost
						{FirstPacketNumber: 9, LastPacketNumber: 9},
						{FirstPacketNumber: 6, LastPacketNumber: 7},
						{FirstPacketNumber: 3, LastPacketNumber: 3},
						{FirstPacketNumber: 1, LastPacketNumber: 1},
					},
				}
				err := handler.ReceivedAck(&ack, 1, time.Now())
				Expect(err).ToNot(HaveOccurred())
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(2)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(4)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(5)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(8)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(10)))
			})

			It("processes an ACK frame that would be sent after a late arrival of a packet", func() {
				largestObserved := 6
				ack1 := frames.AckFrame{
					LargestAcked: protocol.PacketNumber(largestObserved),
					LowestAcked:  1,
					AckRanges: []frames.AckRange{
						{FirstPacketNumber: 4, LastPacketNumber: protocol.PacketNumber(largestObserved)},
						{FirstPacketNumber: 1, LastPacketNumber: 2},
					},
				}
				err := handler.ReceivedAck(&ack1, 1, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 5)))
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(3)))
				ack2 := frames.AckFrame{
					LargestAcked: protocol.PacketNumber(largestObserved),
					LowestAcked:  1,
				}
				err = handler.ReceivedAck(&ack2, 2, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 6)))
				Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(7)))
			})

			It("processes an ACK frame that would be sent after a late arrival of a packet and another packet", func() {
				ack1 := frames.AckFrame{
					LargestAcked: 6,
					LowestAcked:  1,
					AckRanges: []frames.AckRange{
						{FirstPacketNumber: 4, LastPacketNumber: 6},
						{FirstPacketNumber: 1, LastPacketNumber: 2},
					},
				}
				err := handler.ReceivedAck(&ack1, 1, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 5)))
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(3)))
				ack2 := frames.AckFrame{
					LargestAcked: 7,
					LowestAcked:  1,
				}
				err = handler.ReceivedAck(&ack2, 2, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 7)))
				Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(8)))
			})

			It("processes an ACK that contains old ACK ranges", func() {
				ack1 := frames.AckFrame{
					LargestAcked: 6,
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack1, 1, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(7)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 6)))
				ack2 := frames.AckFrame{
					LargestAcked: 10,
					LowestAcked:  1,
					AckRanges: []frames.AckRange{
						{FirstPacketNumber: 8, LastPacketNumber: 10},
						{FirstPacketNumber: 3, LastPacketNumber: 3},
						{FirstPacketNumber: 1, LastPacketNumber: 1},
					},
				}
				err = handler.ReceivedAck(&ack2, 2, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 6 - 3)))
				Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(7)))
				Expect(handler.packetHistory.Back().Value.PacketNumber).To(Equal(protocol.PacketNumber(12)))
			})
		})

		Context("calculating RTT", func() {
			It("computes the RTT", func() {
				now := time.Now()
				// First, fake the sent times of the first, second and last packet
				getPacketElement(1).Value.SendTime = now.Add(-10 * time.Minute)
				getPacketElement(2).Value.SendTime = now.Add(-5 * time.Minute)
				getPacketElement(6).Value.SendTime = now.Add(-1 * time.Minute)
				// Now, check that the proper times are used when calculating the deltas
				err := handler.ReceivedAck(&frames.AckFrame{LargestAcked: 1}, 1, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 10*time.Minute, 1*time.Second))
				err = handler.ReceivedAck(&frames.AckFrame{LargestAcked: 2}, 2, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
				err = handler.ReceivedAck(&frames.AckFrame{LargestAcked: 6}, 3, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 1*time.Minute, 1*time.Second))
			})

			It("uses the DelayTime in the ack frame", func() {
				now := time.Now()
				getPacketElement(1).Value.SendTime = now.Add(-10 * time.Minute)
				err := handler.ReceivedAck(&frames.AckFrame{LargestAcked: 1, DelayTime: 5 * time.Minute}, 1, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
			})
		})
	})

	Context("Retransmission handling", func() {
		var packets []*Packet

		BeforeEach(func() {
			packets = []*Packet{
				{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 4, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 5, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 6, Frames: []frames.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 7, Frames: []frames.Frame{&streamFrame}, Length: 1},
			}
			for _, packet := range packets {
				handler.SentPacket(packet)
			}
			// Increase RTT, because the tests would be flaky otherwise
			handler.rttStats.UpdateRTT(time.Minute, 0, time.Now())
			// Ack a single packet so that we have non-RTO timings
			handler.ReceivedAck(&frames.AckFrame{LargestAcked: 2, LowestAcked: 2}, 1, time.Now())
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(6)))
		})

		It("does not dequeue a packet if no ack has been received", func() {
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("dequeues a packet for retransmission", func() {
			getPacketElement(1).Value.SendTime = time.Now().Add(-time.Hour)
			handler.OnAlarm()
			Expect(getPacketElement(1)).To(BeNil())
			Expect(handler.retransmissionQueue).To(HaveLen(1))
			Expect(handler.retransmissionQueue[0].PacketNumber).To(Equal(protocol.PacketNumber(1)))
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		Context("StopWaitings", func() {
			It("gets a StopWaitingFrame", func() {
				ack := frames.AckFrame{LargestAcked: 5, LowestAcked: 5}
				err := handler.ReceivedAck(&ack, 2, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetStopWaitingFrame(false)).To(Equal(&frames.StopWaitingFrame{LeastUnacked: 6}))
			})

			It("gets a StopWaitingFrame after queueing a retransmission", func() {
				handler.queuePacketForRetransmission(getPacketElement(5))
				Expect(handler.GetStopWaitingFrame(false)).To(Equal(&frames.StopWaitingFrame{LeastUnacked: 6}))
			})
		})
	})

	It("calculates bytes in flight", func() {
		packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
		packet2 := Packet{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, Length: 2}
		packet3 := Packet{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, Length: 3}
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
		ack := frames.AckFrame{
			LargestAcked: 3,
			LowestAcked:  1,
			AckRanges: []frames.AckRange{
				{FirstPacketNumber: 3, LastPacketNumber: 3},
				{FirstPacketNumber: 1, LastPacketNumber: 1},
			},
		}
		err = handler.ReceivedAck(&ack, 1, time.Now())
		Expect(err).NotTo(HaveOccurred())
		Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))

		handler.packetHistory.Front().Value.SendTime = time.Now().Add(-time.Hour)
		handler.OnAlarm()

		Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(0)))
	})

	Context("congestion", func() {
		var (
			cong *mockCongestion
		)

		BeforeEach(func() {
			cong = &mockCongestion{}
			handler.congestion = cong
		})

		It("should call OnSent", func() {
			p := &Packet{
				PacketNumber: 1,
				Length:       42,
			}
			err := handler.SentPacket(p)
			Expect(err).NotTo(HaveOccurred())
			Expect(cong.argsOnPacketSent[1]).To(Equal(protocol.ByteCount(42)))
			Expect(cong.argsOnPacketSent[2]).To(Equal(protocol.PacketNumber(1)))
			Expect(cong.argsOnPacketSent[3]).To(Equal(protocol.ByteCount(42)))
			Expect(cong.argsOnPacketSent[4]).To(BeTrue())
		})

		It("should call MaybeExitSlowStart and OnPacketAcked", func() {
			handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
			handler.SentPacket(&Packet{PacketNumber: 2, Frames: []frames.Frame{}, Length: 1})
			err := handler.ReceivedAck(&frames.AckFrame{LargestAcked: 1, LowestAcked: 1}, 1, time.Now())
			Expect(err).NotTo(HaveOccurred())
			Expect(cong.maybeExitSlowStart).To(BeTrue())
			Expect(cong.packetsAcked).To(BeEquivalentTo([][]interface{}{
				{protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(1)},
			}))
			Expect(cong.packetsLost).To(BeEmpty())
		})

		It("should call MaybeExitSlowStart and OnPacketLost", func() {
			handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
			handler.SentPacket(&Packet{PacketNumber: 2, Frames: []frames.Frame{}, Length: 1})
			handler.SentPacket(&Packet{PacketNumber: 3, Frames: []frames.Frame{}, Length: 1})
			handler.OnAlarm() // RTO, meaning 2 lost packets
			Expect(cong.maybeExitSlowStart).To(BeFalse())
			Expect(cong.onRetransmissionTimeout).To(BeTrue())
			Expect(cong.packetsAcked).To(BeEmpty())
			Expect(cong.packetsLost).To(BeEquivalentTo([][]interface{}{
				{protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(2)},
				{protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(1)},
			}))
		})

		It("allows or denies sending based on congestion", func() {
			Expect(handler.SendingAllowed()).To(BeTrue())
			err := handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: protocol.DefaultTCPMSS + 1})
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.SendingAllowed()).To(BeFalse())
		})

		It("allows or denies sending based on the number of tracked packets", func() {
			Expect(handler.SendingAllowed()).To(BeTrue())
			handler.retransmissionQueue = make([]*Packet, protocol.MaxTrackedSentPackets)
			Expect(handler.SendingAllowed()).To(BeFalse())
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
			err := handler.SentPacket(&Packet{PacketNumber: 1, Length: 1})
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(&Packet{PacketNumber: 2, Length: 1})
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeTrue())

			err = handler.ReceivedAck(&frames.AckFrame{LargestAcked: 2, LowestAcked: 2}, 1, time.Now().Add(time.Hour))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeFalse())

			// RTT is around 1h now.
			// The formula is (1+1/8) * RTT, so this should be around that number
			Expect(handler.lossTime.Sub(time.Now())).To(BeNumerically("~", time.Hour*9/8, time.Minute))
			Expect(handler.GetAlarmTimeout().Sub(time.Now())).To(BeNumerically("~", time.Hour*9/8, time.Minute))

			handler.packetHistory.Front().Value.SendTime = time.Now().Add(-2 * time.Hour)
			handler.OnAlarm()
			Expect(handler.DequeuePacketForRetransmission()).NotTo(BeNil())
		})

		It("does not detect packets as lost without ACKs", func() {
			err := handler.SentPacket(&Packet{PacketNumber: 1, Length: 1})
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(&Packet{PacketNumber: 2, Length: 1})
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(&Packet{PacketNumber: 3, Length: 1})
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeTrue())

			err = handler.ReceivedAck(&frames.AckFrame{LargestAcked: 1, LowestAcked: 1}, 1, time.Now().Add(time.Hour))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeTrue())
			Expect(handler.GetAlarmTimeout().Sub(time.Now())).To(BeNumerically("~", handler.computeRTOTimeout(), time.Minute))

			// This means RTO, so both packets should be lost
			handler.OnAlarm()
			Expect(handler.DequeuePacketForRetransmission()).ToNot(BeNil())
			Expect(handler.DequeuePacketForRetransmission()).ToNot(BeNil())
		})
	})

	Context("RTO retransmission", func() {
		It("queues two packets if RTO expires", func() {
			err := handler.SentPacket(&Packet{PacketNumber: 1, Length: 1})
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(&Packet{PacketNumber: 2, Length: 1})
			Expect(err).NotTo(HaveOccurred())

			handler.rttStats.UpdateRTT(time.Hour, 0, time.Now())
			Expect(handler.lossTime.IsZero()).To(BeTrue())
			Expect(handler.GetAlarmTimeout().Sub(time.Now())).To(BeNumerically("~", handler.computeRTOTimeout(), time.Minute))

			handler.OnAlarm()
			Expect(handler.DequeuePacketForRetransmission()).ToNot(BeNil())
			Expect(handler.DequeuePacketForRetransmission()).ToNot(BeNil())

			Expect(handler.rtoCount).To(BeEquivalentTo(1))
		})
	})
})
