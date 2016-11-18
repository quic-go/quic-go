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
	nCalls                  int
	argsOnPacketSent        []interface{}
	argsOnCongestionEvent   []interface{}
	onRetransmissionTimeout bool
}

func (m *mockCongestion) TimeUntilSend(now time.Time, bytesInFlight protocol.ByteCount) time.Duration {
	panic("not implemented")
}

func (m *mockCongestion) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) bool {
	m.nCalls++
	m.argsOnPacketSent = []interface{}{sentTime, bytesInFlight, packetNumber, bytes, isRetransmittable}
	return false
}

func (m *mockCongestion) GetCongestionWindow() protocol.ByteCount {
	m.nCalls++
	return protocol.DefaultTCPMSS
}

func (m *mockCongestion) OnCongestionEvent(rttUpdated bool, bytesInFlight protocol.ByteCount, ackedPackets congestion.PacketVector, lostPackets congestion.PacketVector) {
	m.nCalls++
	m.argsOnCongestionEvent = []interface{}{rttUpdated, bytesInFlight, ackedPackets, lostPackets}
}

func (m *mockCongestion) OnRetransmissionTimeout(packetsRetransmitted bool) {
	m.nCalls++
	m.onRetransmissionTimeout = true
}

func (m *mockCongestion) RetransmissionDelay() time.Duration {
	return protocol.DefaultRetransmissionTime
}

func (m *mockCongestion) SetNumEmulatedConnections(n int)         { panic("not implemented") }
func (m *mockCongestion) OnConnectionMigration()                  { panic("not implemented") }
func (m *mockCongestion) SetSlowStartLargeReduction(enabled bool) { panic("not implemented") }

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
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
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
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(1)))
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
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(1)))
		})

		It("stores the sent time", func() {
			packet := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
			err := handler.SentPacket(&packet)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory.Front().Value.SendTime.Unix()).To(BeNumerically("~", time.Now().Unix(), 1))
		})

		It("updates the last sent time", func() {
			packet := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
			err := handler.SentPacket(&packet)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.lastSentPacketTime.Unix()).To(BeNumerically("~", time.Now().Unix(), 1))
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
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
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
			for i := protocol.PacketNumber(1); i < protocol.MaxTrackedSentPackets+10; i++ {
				packet := Packet{PacketNumber: protocol.PacketNumber(i), Frames: []frames.Frame{&streamFrame}, Length: 1}
				err := handler.SentPacket(&packet)
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.CheckForError()
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
				handler.SentPacket(packet)
			}
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets))))
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
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337, time.Now())
				Expect(err).To(MatchError(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects out of order ACKs", func() {
				ack := frames.AckFrame{
					LargestAcked: 3,
				}
				err := handler.ReceivedAck(&ack, 1337, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337-1, time.Now())
				Expect(err).To(MatchError(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.LargestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects ACKs with a too high LargestAcked packet number", func() {
				ack := frames.AckFrame{
					LargestAcked: packets[len(packets)-1].PacketNumber + 1337,
				}
				err := handler.ReceivedAck(&ack, 1, time.Now())
				Expect(err).To(MatchError(errAckForUnsentPacket))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets))))
			})

			It("ignores repeated ACKs", func() {
				ack := frames.AckFrame{
					LargestAcked: 3,
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack, 1337, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337+1, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.LargestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects ACKs for skipped packets", func() {
				ack := frames.AckFrame{
					LargestAcked: 12,
					LowestAcked:  5,
				}
				err := handler.ReceivedAck(&ack, 1337, time.Now())
				Expect(err).To(MatchError(ErrAckForSkippedPacket))
				Expect(handler.LargestAcked).To(BeZero())
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
					Expect(el.Value.MissingReports).To(BeZero())
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
				Expect(el.Value.MissingReports).To(BeZero())
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(10)))
				Expect(el.Value.MissingReports).To(BeZero())
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
				Expect(el.Value.MissingReports).To(Equal(uint8(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(5)))
				Expect(el.Value.MissingReports).To(Equal(uint8(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(10)))
				Expect(el.Value.MissingReports).To(BeZero())
				Expect(el.Next().Value.PacketNumber).To(Equal(protocol.PacketNumber(12)))
			})

			It("NACKs packets below the LowestAcked", func() {
				ack := frames.AckFrame{
					LargestAcked: 8,
					LowestAcked:  3,
				}
				err := handler.ReceivedAck(&ack, 1, time.Now())
				Expect(err).ToNot(HaveOccurred())
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
				Expect(el.Value.MissingReports).To(Equal(uint8(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(2)))
				Expect(el.Value.MissingReports).To(Equal(uint8(1)))
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
				Expect(el.Value.MissingReports).To(Equal(uint8(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(4)))
				Expect(el.Value.MissingReports).To(Equal(uint8(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(5)))
				Expect(el.Value.MissingReports).To(Equal(uint8(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(8)))
				Expect(el.Value.MissingReports).To(Equal(uint8(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(10)))
				Expect(el.Value.MissingReports).To(BeZero())
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
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 5)))
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(3)))
				ack2 := frames.AckFrame{
					LargestAcked: protocol.PacketNumber(largestObserved),
					LowestAcked:  1,
				}
				err = handler.ReceivedAck(&ack2, 2, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 6)))
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
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 5)))
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(3)))
				ack2 := frames.AckFrame{
					LargestAcked: 7,
					LowestAcked:  1,
				}
				err = handler.ReceivedAck(&ack2, 2, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 7)))
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
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 6)))
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
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 6 - 3)))
				Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(7)))
				Expect(handler.packetHistory.Back().Value.PacketNumber).To(Equal(protocol.PacketNumber(12)))
			})
		})

		Context("calculating RTT", func() {
			It("calculates the RTT", func() {
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

	Context("Retransmission handler", func() {
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
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(7)))
		})

		It("does not dequeue a packet if no packet has been nacked", func() {
			for i := uint8(0); i < protocol.RetransmissionThreshold; i++ {
				el := getPacketElement(2)
				Expect(el).ToNot(BeNil())
				handler.nackPacket(el)
			}
			Expect(getPacketElement(2)).ToNot(BeNil())
			handler.MaybeQueueRTOs()
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("queues a packet for retransmission", func() {
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				el := getPacketElement(2)
				Expect(el).ToNot(BeNil())
				handler.nackPacket(el)
			}
			Expect(getPacketElement(2)).To(BeNil())
			handler.MaybeQueueRTOs()
			Expect(handler.retransmissionQueue).To(HaveLen(1))
			Expect(handler.retransmissionQueue[0].PacketNumber).To(Equal(protocol.PacketNumber(2)))
		})

		It("dequeues a packet for retransmission", func() {
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				el := getPacketElement(3)
				Expect(el).ToNot(BeNil())
				handler.nackPacket(el)
			}
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("keeps the packets in the right order", func() {
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				el := getPacketElement(4)
				Expect(el).ToNot(BeNil())
				handler.nackPacket(el)
			}
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				el := getPacketElement(2)
				Expect(el).ToNot(BeNil())
				handler.nackPacket(el)
			}
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(2)))
			packet = handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(4)))
		})

		Context("StopWaitings", func() {
			It("gets a StopWaitingFrame", func() {
				ack := frames.AckFrame{LargestAcked: 5, LowestAcked: 5}
				err := handler.ReceivedAck(&ack, 1, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetStopWaitingFrame(false)).To(Equal(&frames.StopWaitingFrame{LeastUnacked: 6}))
			})

			It("gets a StopWaitingFrame after queueing a retransmission", func() {
				handler.queuePacketForRetransmission(getPacketElement(5))
				Expect(handler.GetStopWaitingFrame(false)).To(Equal(&frames.StopWaitingFrame{LeastUnacked: 6}))
			})
		})
	})

	Context("calculating bytes in flight", func() {
		It("works in a typical retransmission scenarios", func() {
			packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
			packet2 := Packet{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, Length: 2}
			packet3 := Packet{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, Length: 3}
			err := handler.SentPacket(&packet1)
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(&packet3)
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(1 + 2 + 3)))

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
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(2)))

			// Simulate protocol.RetransmissionThreshold more NACKs
			for i := uint8(0); i < protocol.RetransmissionThreshold; i++ {
				el := getPacketElement(2)
				Expect(el).ToNot(BeNil())
				handler.nackPacket(el)
			}
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(0)))

			// Retransmission
			packet4 := Packet{PacketNumber: 4, Length: 2}
			err = handler.SentPacket(&packet4)
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(2)))

			// ACK
			ack = frames.AckFrame{
				LargestAcked: 4,
				LowestAcked:  1,
			}
			err = handler.ReceivedAck(&ack, 2, time.Now())
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(0)))
		})
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
				Frames:       []frames.Frame{&frames.StreamFrame{StreamID: 5}},
				Length:       42,
			}
			err := handler.SentPacket(p)
			Expect(err).NotTo(HaveOccurred())
			Expect(cong.nCalls).To(Equal(1))
			Expect(cong.argsOnPacketSent[1]).To(Equal(protocol.ByteCount(42)))
			Expect(cong.argsOnPacketSent[2]).To(Equal(protocol.PacketNumber(1)))
			Expect(cong.argsOnPacketSent[3]).To(Equal(protocol.ByteCount(42)))
			Expect(cong.argsOnPacketSent[4]).To(BeTrue())
		})

		It("should call OnCongestionEvent", func() {
			handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
			handler.SentPacket(&Packet{PacketNumber: 2, Frames: []frames.Frame{}, Length: 2})
			handler.SentPacket(&Packet{PacketNumber: 3, Frames: []frames.Frame{}, Length: 3})
			ack := frames.AckFrame{
				LargestAcked: 3,
				LowestAcked:  1,
				AckRanges: []frames.AckRange{
					{FirstPacketNumber: 3, LastPacketNumber: 3},
					{FirstPacketNumber: 1, LastPacketNumber: 1},
				},
			}
			err := handler.ReceivedAck(&ack, 1, time.Now())
			Expect(err).NotTo(HaveOccurred())
			Expect(cong.nCalls).To(Equal(4)) // 3 * SentPacket + 1 * ReceivedAck
			// rttUpdated, bytesInFlight, ackedPackets, lostPackets
			Expect(cong.argsOnCongestionEvent[0]).To(BeTrue())
			Expect(cong.argsOnCongestionEvent[1]).To(Equal(protocol.ByteCount(2)))
			Expect(cong.argsOnCongestionEvent[2]).To(Equal(congestion.PacketVector{{Number: 1, Length: 1}, {Number: 3, Length: 3}}))
			Expect(cong.argsOnCongestionEvent[3]).To(BeEmpty())

			// Loose the packet
			var packetNumber protocol.PacketNumber
			for i := uint8(0); i < protocol.RetransmissionThreshold; i++ {
				packetNumber = protocol.PacketNumber(4 + i)
				handler.SentPacket(&Packet{PacketNumber: packetNumber, Frames: []frames.Frame{}, Length: protocol.ByteCount(packetNumber)})
				ack := frames.AckFrame{
					LargestAcked: packetNumber,
					LowestAcked:  1,
					AckRanges: []frames.AckRange{
						{FirstPacketNumber: 3, LastPacketNumber: packetNumber},
						{FirstPacketNumber: 1, LastPacketNumber: 1},
					},
				}
				err = handler.ReceivedAck(&ack, protocol.PacketNumber(2+i), time.Now())
				Expect(err).NotTo(HaveOccurred())
			}

			Expect(cong.argsOnCongestionEvent[2]).To(Equal(congestion.PacketVector{{Number: packetNumber, Length: protocol.ByteCount(packetNumber)}}))
			Expect(cong.argsOnCongestionEvent[3]).To(Equal(congestion.PacketVector{{Number: 2, Length: 2}}))
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

		It("should call OnRetransmissionTimeout", func() {
			err := handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
			Expect(err).NotTo(HaveOccurred())
			handler.lastSentPacketTime = time.Now().Add(-time.Second)
			handler.MaybeQueueRTOs()
			Expect(cong.nCalls).To(Equal(3))
			// rttUpdated, bytesInFlight, ackedPackets, lostPackets
			Expect(cong.argsOnCongestionEvent[0]).To(BeFalse())
			Expect(cong.argsOnCongestionEvent[1]).To(Equal(protocol.ByteCount(1)))
			Expect(cong.argsOnCongestionEvent[2]).To(BeEmpty())
			Expect(cong.argsOnCongestionEvent[3]).To(Equal(congestion.PacketVector{{Number: 1, Length: 1}}))
			Expect(cong.onRetransmissionTimeout).To(BeTrue())
		})
	})

	Context("calculating RTO", func() {
		It("uses default RTO", func() {
			Expect(handler.getRTO()).To(Equal(protocol.DefaultRetransmissionTime))
		})

		It("uses RTO from rttStats", func() {
			rtt := time.Second
			expected := rtt + rtt/2*4
			handler.rttStats.UpdateRTT(rtt, 0, time.Now())
			Expect(handler.getRTO()).To(Equal(expected))
		})

		It("limits RTO min", func() {
			rtt := time.Millisecond
			handler.rttStats.UpdateRTT(rtt, 0, time.Now())
			Expect(handler.getRTO()).To(Equal(protocol.MinRetransmissionTime))
		})

		It("limits RTO max", func() {
			rtt := time.Hour
			handler.rttStats.UpdateRTT(rtt, 0, time.Now())
			Expect(handler.getRTO()).To(Equal(protocol.MaxRetransmissionTime))
		})

		It("implements exponential backoff", func() {
			handler.consecutiveRTOCount = 0
			Expect(handler.getRTO()).To(Equal(protocol.DefaultRetransmissionTime))
			handler.consecutiveRTOCount = 1
			Expect(handler.getRTO()).To(Equal(2 * protocol.DefaultRetransmissionTime))
			handler.consecutiveRTOCount = 2
			Expect(handler.getRTO()).To(Equal(4 * protocol.DefaultRetransmissionTime))
		})
	})

	Context("RTO retransmission", func() {
		Context("calculating the time to first RTO", func() {
			It("defaults to zero", func() {
				Expect(handler.TimeOfFirstRTO().IsZero()).To(BeTrue())
			})

			It("returns time to RTO", func() {
				err := handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.TimeOfFirstRTO().Sub(time.Now())).To(BeNumerically("~", protocol.DefaultRetransmissionTime, time.Millisecond))
			})
		})

		Context("queuing packets due to RTO", func() {
			It("does nothing if not required", func() {
				err := handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
				Expect(err).NotTo(HaveOccurred())
				handler.MaybeQueueRTOs()
				Expect(handler.retransmissionQueue).To(BeEmpty())
			})

			It("queues a packet if RTO expired", func() {
				p := &Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1}
				err := handler.SentPacket(p)
				Expect(err).NotTo(HaveOccurred())
				handler.lastSentPacketTime = time.Now().Add(-time.Second)
				handler.MaybeQueueRTOs()
				Expect(handler.retransmissionQueue).To(HaveLen(1))
				Expect(handler.retransmissionQueue[0].PacketNumber).To(Equal(p.PacketNumber))
				Expect(time.Now().Sub(handler.lastSentPacketTime)).To(BeNumerically("<", time.Second/2))
			})

			It("queues two packets if RTO expired", func() {
				for i := 1; i < 4; i++ {
					p := &Packet{PacketNumber: protocol.PacketNumber(i), Length: 1}
					err := handler.SentPacket(p)
					Expect(err).NotTo(HaveOccurred())
				}
				handler.lastSentPacketTime = time.Now().Add(-time.Second)
				handler.MaybeQueueRTOs()
				Expect(handler.retransmissionQueue).To(HaveLen(2))
				Expect(handler.retransmissionQueue[0].PacketNumber).To(Equal(protocol.PacketNumber(1)))
				Expect(handler.retransmissionQueue[1].PacketNumber).To(Equal(protocol.PacketNumber(2)))
				Expect(time.Now().Sub(handler.lastSentPacketTime)).To(BeNumerically("<", time.Second/2))
				Expect(handler.consecutiveRTOCount).To(Equal(uint32(1)))
			})
		})

		It("works with DequeuePacketForRetransmission", func() {
			p := &Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1}
			err := handler.SentPacket(p)
			Expect(err).NotTo(HaveOccurred())
			handler.lastSentPacketTime = time.Now().Add(-time.Second)
			handler.MaybeQueueRTOs()
			Expect(handler.DequeuePacketForRetransmission().PacketNumber).To(Equal(p.PacketNumber))
		})
	})
})
