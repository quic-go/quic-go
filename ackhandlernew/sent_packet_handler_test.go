package ackhandlernew

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

type mockStopWaiting struct {
	receivedAckForPacketNumber protocol.PacketNumber
}

func (m *mockStopWaiting) RegisterPacketForRetransmission(packet *Packet) { panic("not implemented") }
func (m *mockStopWaiting) GetStopWaitingFrame() *frames.StopWaitingFrame  { panic("not implemented") }
func (m *mockStopWaiting) SentStopWaitingWithPacket(packetNumber protocol.PacketNumber) {
	panic("not implemented")
}
func (m *mockStopWaiting) ReceivedAckForPacketNumber(packetNumber protocol.PacketNumber) {
	m.receivedAckForPacketNumber = packetNumber
}

var _ = Describe("SentPacketHandler", func() {
	var (
		handler     *sentPacketHandler
		streamFrame frames.StreamFrame
	)

	BeforeEach(func() {
		stopWaitingManager := &mockStopWaiting{}
		handler = NewSentPacketHandler(stopWaitingManager).(*sentPacketHandler)
		streamFrame = frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}
	})

	It("informs the StopWaitingManager about ACKs received", func() {
		handler.ackPacket(2)
		Expect(handler.stopWaitingManager.(*mockStopWaiting).receivedAckForPacketNumber).To(Equal(protocol.PacketNumber(2)))
	})

	It("gets the LargestAcked packet number", func() {
		handler.LargestAcked = 0x1337
		Expect(handler.GetLargestAcked()).To(Equal(protocol.PacketNumber(0x1337)))
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
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.packetHistory[1].PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.packetHistory[2].PacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
		})

		It("rejects packets with the same packet number", func() {
			packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
			packet2 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).To(MatchError(errDuplicatePacketNumber))
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(1)))
		})

		It("works with non-consecutive packet numbers", func() {
			packet1 := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
			packet2 := Packet{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(3)))
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
		})

		It("stores the sent time", func() {
			packet := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
			err := handler.SentPacket(&packet)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory[1].sendTime.Unix()).To(BeNumerically("~", time.Now().Unix(), 1))
		})

		It("updates the last sent time", func() {
			packet := Packet{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, Length: 1}
			err := handler.SentPacket(&packet)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.lastSentPacketTime.Unix()).To(BeNumerically("~", time.Now().Unix(), 1))
		})
	})

	Context("DOS mitigation", func() {
		It("checks the size of the packet history, for unacked packets", func() {
			for i := uint32(1); i < protocol.MaxTrackedSentPackets+10; i++ {
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
			}
			for _, packet := range packets {
				handler.SentPacket(packet)
			}
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets))))
		})

		Context("ACK validation", func() {
			It("rejects duplicate ACKs", func() {
				largestAcked := 3
				ack := frames.AckFrameNew{
					LargestAcked: protocol.PacketNumber(largestAcked),
				}
				err := handler.ReceivedAck(&ack, 1337)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337)
				Expect(err).To(MatchError(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects out of order ACKs", func() {
				ack := frames.AckFrameNew{
					LargestAcked: 3,
				}
				err := handler.ReceivedAck(&ack, 1337)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337-1)
				Expect(err).To(MatchError(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.LargestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects ACKs with a too high LargestAcked packet number", func() {
				ack := frames.AckFrameNew{
					LargestAcked: packets[len(packets)-1].PacketNumber + 1337,
				}
				err := handler.ReceivedAck(&ack, 1)
				Expect(err).To(MatchError(errAckForUnsentPacket))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(len(packets))))
			})
		})

		Context("acks and nacks the right packets", func() {
			// if a packet is ACKed, it's removed from the packet history

			It("adjusts the LargestInOrderAcked", func() {
				ack := frames.AckFrameNew{
					LargestAcked: 5,
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack, 1)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.LargestInOrderAcked).To(Equal(protocol.PacketNumber(5)))
				for i := 1; i <= 5; i++ {
					Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(i)))
				}
				for i := 6; i <= 10; i++ {
					Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(i)))
					Expect(handler.packetHistory[protocol.PacketNumber(i)].MissingReports).To(BeZero())
				}
			})

			It("ACKs all packets for an ACK frame with no missing packets", func() {
				ack := frames.AckFrameNew{
					LargestAcked: 8,
					LowestAcked:  2,
				}
				err := handler.ReceivedAck(&ack, 1)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.LargestInOrderAcked).To(Equal(protocol.PacketNumber(0)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
				for i := 2; i <= 8; i++ {
					Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(i)))
				}
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(9)))
				Expect(handler.packetHistory[9].MissingReports).To(BeZero())
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(10)))
				Expect(handler.packetHistory[10].MissingReports).To(BeZero())
			})

			It("handles an ACK frame with one missing packet range", func() {
				ack := frames.AckFrameNew{
					LargestAcked: 9,
					LowestAcked:  2,
					AckRanges: []frames.AckRange{ // packets 4 and 5 were lost
						{FirstPacketNumber: 6, LastPacketNumber: 9},
						{FirstPacketNumber: 2, LastPacketNumber: 3},
					},
				}
				err := handler.ReceivedAck(&ack, 1)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.LargestInOrderAcked).To(Equal(protocol.PacketNumber(0)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
				for i := 2; i <= 3; i++ {
					Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(i)))
				}
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(4)))
				Expect(handler.packetHistory[4].MissingReports).To(Equal(uint8(1)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(5)))
				Expect(handler.packetHistory[5].MissingReports).To(Equal(uint8(1)))
				for i := 6; i <= 9; i++ {
					Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(i)))
				}
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(10)))
				Expect(handler.packetHistory[10].MissingReports).To(BeZero())
			})

			It("NACKs packets below the LowestAcked", func() {
				ack := frames.AckFrameNew{
					LargestAcked: 8,
					LowestAcked:  3,
				}
				err := handler.ReceivedAck(&ack, 1)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
				Expect(handler.packetHistory[1].MissingReports).To(Equal(uint8(1)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(2)))
				Expect(handler.packetHistory[2].MissingReports).To(Equal(uint8(1)))
			})

			It("handles an ACK with multiple missing packet ranges", func() {
				ack := frames.AckFrameNew{
					LargestAcked: 9,
					LowestAcked:  1,
					AckRanges: []frames.AckRange{ // packets 2, 4 and 5, and 8 were lost
						{FirstPacketNumber: 9, LastPacketNumber: 9},
						{FirstPacketNumber: 6, LastPacketNumber: 7},
						{FirstPacketNumber: 3, LastPacketNumber: 3},
						{FirstPacketNumber: 1, LastPacketNumber: 1},
					},
				}
				err := handler.ReceivedAck(&ack, 1)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.LargestInOrderAcked).To(Equal(protocol.PacketNumber(1)))
				Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(1)))
				Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(3)))
				Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(6)))
				Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(7)))
				Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(9)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(2)))
				Expect(handler.packetHistory[2].MissingReports).To(Equal(uint8(1)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(4)))
				Expect(handler.packetHistory[4].MissingReports).To(Equal(uint8(1)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(5)))
				Expect(handler.packetHistory[5].MissingReports).To(Equal(uint8(1)))
				Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(8)))
				Expect(handler.packetHistory[8].MissingReports).To(Equal(uint8(1)))
				Expect(handler.packetHistory[10].MissingReports).To(BeZero())
			})
		})

		Context("calculating RTT", func() {
			It("calculates the RTT", func() {
				now := time.Now()
				// First, fake the sent times of the first, second and last packet
				handler.packetHistory[1].sendTime = now.Add(-10 * time.Minute)
				handler.packetHistory[2].sendTime = now.Add(-5 * time.Minute)
				handler.packetHistory[6].sendTime = now.Add(-1 * time.Minute)
				// Now, check that the proper times are used when calculating the deltas
				err := handler.ReceivedAck(&frames.AckFrameNew{LargestAcked: 1}, 1)
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 10*time.Minute, 1*time.Second))
				err = handler.ReceivedAck(&frames.AckFrameNew{LargestAcked: 2}, 2)
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
				err = handler.ReceivedAck(&frames.AckFrameNew{LargestAcked: 6}, 3)
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 1*time.Minute, 1*time.Second))
			})

			It("uses the DelayTime in the ack frame", func() {
				now := time.Now()
				handler.packetHistory[1].sendTime = now.Add(-10 * time.Minute)
				err := handler.ReceivedAck(&frames.AckFrameNew{LargestAcked: 1, DelayTime: 5 * time.Minute}, 1)
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
				_, err := handler.nackPacket(2)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.ProbablyHasPacketForRetransmission()).To(BeFalse())
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("queues a packet for retransmission", func() {
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				_, err := handler.nackPacket(2)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.ProbablyHasPacketForRetransmission()).To(BeTrue())
			Expect(handler.retransmissionQueue).To(HaveLen(1))
			Expect(handler.retransmissionQueue[0].PacketNumber).To(Equal(protocol.PacketNumber(2)))
		})

		It("dequeues a packet for retransmission", func() {
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				_, err := handler.nackPacket(3)
				Expect(err).ToNot(HaveOccurred())
			}
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("deletes a packet from the packetHistory map when sending out the retransmission", func() {
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				_, err := handler.nackPacket(3)
				Expect(err).ToNot(HaveOccurred())
			}
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(3)))
		})

		It("keeps the packets in the right order", func() {
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				_, err := handler.nackPacket(4)
				Expect(err).ToNot(HaveOccurred())
			}
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				_, err := handler.nackPacket(2)
				Expect(err).ToNot(HaveOccurred())
			}
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(2)))
			packet = handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(4)))
		})

		It("only queues each packet once, regardless of the number of NACKs", func() {
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				_, err := handler.nackPacket(4)
				Expect(err).ToNot(HaveOccurred())
			}
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				_, err := handler.nackPacket(2)
				Expect(err).ToNot(HaveOccurred())
			}
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				_, err := handler.nackPacket(4)
				Expect(err).ToNot(HaveOccurred())
			}
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			packet = handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("changes the LargestInOrderAcked after queueing the lowest packet for retransmission", func() {
			ack := frames.AckFrameNew{
				LargestAcked: 7,
				LowestAcked:  1,
				AckRanges: []frames.AckRange{
					{FirstPacketNumber: 7, LastPacketNumber: 7},
					{FirstPacketNumber: 4, LastPacketNumber: 5},
					{FirstPacketNumber: 1, LastPacketNumber: 2},
				},
			}
			err := handler.ReceivedAck(&ack, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.LargestInOrderAcked).To(Equal(protocol.PacketNumber(2)))
			// this will trigger a retransmission of packet 3
			for i := uint8(0); i < protocol.RetransmissionThreshold; i++ {
				handler.nackPacket(3)
			}
			Expect(handler.LargestInOrderAcked).To(Equal(protocol.PacketNumber(5)))
		})

		It("does not change the LargestInOrderAcked after queueing a higher packet for retransmission", func() {
			ack := frames.AckFrameNew{
				LargestAcked: 7,
				LowestAcked:  1,
				AckRanges: []frames.AckRange{
					{FirstPacketNumber: 7, LastPacketNumber: 7},
					{FirstPacketNumber: 4, LastPacketNumber: 5},
					{FirstPacketNumber: 1, LastPacketNumber: 2},
				},
			}
			err := handler.ReceivedAck(&ack, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.LargestInOrderAcked).To(Equal(protocol.PacketNumber(2)))
			// this will trigger a retransmission of packet 6
			for i := uint8(0); i < protocol.RetransmissionThreshold; i++ {
				handler.nackPacket(6)
			}
			Expect(handler.LargestInOrderAcked).To(Equal(protocol.PacketNumber(2)))
		})

		It("does not retransmit a packet if a belated ACK was received", func() {
			// lose packet by NACKing it often enough
			for i := uint8(0); i < protocol.RetransmissionThreshold+1; i++ {
				_, err := handler.nackPacket(2)
				Expect(err).ToNot(HaveOccurred())
			}
			// this is the belated ACK
			handler.ackPacket(2)
			// this is the edge case where ProbablyHasPacketForRetransmission() get's it wrong: it says there's probably a packet for retransmission, but actually there isn't
			Expect(handler.ProbablyHasPacketForRetransmission()).To(BeTrue())
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
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
			ack := frames.AckFrameNew{
				LargestAcked: 3,
				LowestAcked:  1,
				AckRanges: []frames.AckRange{
					{FirstPacketNumber: 3, LastPacketNumber: 3},
					{FirstPacketNumber: 1, LastPacketNumber: 1},
				},
			}
			err = handler.ReceivedAck(&ack, 1)
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(2)))

			// Simulate protocol.RetransmissionThreshold more NACKs
			for i := uint8(0); i < protocol.RetransmissionThreshold; i++ {
				_, err = handler.nackPacket(2)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(0)))

			// Retransmission
			packet4 := Packet{PacketNumber: 4, Length: 2}
			err = handler.SentPacket(&packet4)
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(2)))

			// ACK
			ack = frames.AckFrameNew{
				LargestAcked: 4,
				LowestAcked:  1,
			}
			err = handler.ReceivedAck(&ack, 2)
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
			ack := frames.AckFrameNew{
				LargestAcked: 3,
				LowestAcked:  1,
				AckRanges: []frames.AckRange{
					{FirstPacketNumber: 3, LastPacketNumber: 3},
					{FirstPacketNumber: 1, LastPacketNumber: 1},
				},
			}
			err := handler.ReceivedAck(&ack, 1)
			Expect(err).NotTo(HaveOccurred())
			Expect(cong.nCalls).To(Equal(4)) // 3 * SentPacket + 1 * ReceivedAck
			// rttUpdated, bytesInFlight, ackedPackets, lostPackets
			Expect(cong.argsOnCongestionEvent[0]).To(BeTrue())
			Expect(cong.argsOnCongestionEvent[1]).To(Equal(protocol.ByteCount(2)))
			Expect(cong.argsOnCongestionEvent[2]).To(Equal(congestion.PacketVector{{1, 1}, {3, 3}}))
			Expect(cong.argsOnCongestionEvent[3]).To(BeEmpty())

			// Loose the packet
			var packetNumber protocol.PacketNumber
			for i := uint8(0); i < protocol.RetransmissionThreshold; i++ {
				packetNumber = protocol.PacketNumber(4 + i)
				handler.SentPacket(&Packet{PacketNumber: packetNumber, Frames: []frames.Frame{}, Length: protocol.ByteCount(packetNumber)})
				ack := frames.AckFrameNew{
					LargestAcked: packetNumber,
					LowestAcked:  1,
					AckRanges: []frames.AckRange{
						{FirstPacketNumber: 3, LastPacketNumber: packetNumber},
						{FirstPacketNumber: 1, LastPacketNumber: 1},
					},
				}
				err = handler.ReceivedAck(&ack, protocol.PacketNumber(2+i))
				Expect(err).NotTo(HaveOccurred())
			}

			Expect(cong.argsOnCongestionEvent[2]).To(Equal(congestion.PacketVector{{packetNumber, protocol.ByteCount(packetNumber)}}))
			Expect(cong.argsOnCongestionEvent[3]).To(Equal(congestion.PacketVector{{2, 2}}))
		})

		It("allows or denies sending", func() {
			Expect(handler.CongestionAllowsSending()).To(BeTrue())
			err := handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: protocol.DefaultTCPMSS + 1})
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.CongestionAllowsSending()).To(BeFalse())
		})

		It("should call OnRetransmissionTimeout", func() {
			err := handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
			Expect(err).NotTo(HaveOccurred())
			handler.lastSentPacketTime = time.Now().Add(-time.Second)
			handler.maybeQueuePacketsRTO()
			Expect(cong.nCalls).To(Equal(3))
			// rttUpdated, bytesInFlight, ackedPackets, lostPackets
			Expect(cong.argsOnCongestionEvent[0]).To(BeFalse())
			Expect(cong.argsOnCongestionEvent[1]).To(Equal(protocol.ByteCount(1)))
			Expect(cong.argsOnCongestionEvent[2]).To(BeEmpty())
			Expect(cong.argsOnCongestionEvent[3]).To(Equal(congestion.PacketVector{{1, 1}}))
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

			It("ignores nil packets", func() {
				handler.packetHistory[1] = nil
				handler.maybeQueuePacketsRTO()
				Expect(handler.TimeOfFirstRTO().IsZero()).To(BeTrue())
			})
		})

		Context("queuing packets due to RTO", func() {
			It("does nothing if not required", func() {
				err := handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
				Expect(err).NotTo(HaveOccurred())
				handler.maybeQueuePacketsRTO()
				Expect(handler.retransmissionQueue).To(BeEmpty())
			})

			It("queues a packet if RTO expired", func() {
				p := &Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1}
				err := handler.SentPacket(p)
				Expect(err).NotTo(HaveOccurred())
				handler.lastSentPacketTime = time.Now().Add(-time.Second)
				handler.maybeQueuePacketsRTO()
				Expect(handler.retransmissionQueue).To(HaveLen(1))
				Expect(handler.retransmissionQueue[0]).To(Equal(p))
			})

			It("does not queue retransmittedpackets", func() {
				p := &Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1, Retransmitted: true}
				err := handler.SentPacket(p)
				Expect(err).NotTo(HaveOccurred())
				handler.lastSentPacketTime = time.Now().Add(-time.Second)
				handler.maybeQueuePacketsRTO()
				Expect(handler.retransmissionQueue).To(BeEmpty())
			})

			It("ignores nil packets", func() {
				handler.packetHistory[1] = nil
				handler.maybeQueuePacketsRTO()
				Expect(handler.retransmissionQueue).To(BeEmpty())
			})
		})

		It("works with HasPacketForRetransmission", func() {
			p := &Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1}
			err := handler.SentPacket(p)
			Expect(err).NotTo(HaveOccurred())
			handler.lastSentPacketTime = time.Now().Add(-time.Second)
			Expect(handler.DequeuePacketForRetransmission()).ToNot(BeNil())
		})

		It("works with DequeuePacketForRetransmission", func() {
			p := &Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1}
			err := handler.SentPacket(p)
			Expect(err).NotTo(HaveOccurred())
			handler.lastSentPacketTime = time.Now().Add(-time.Second)
			Expect(handler.DequeuePacketForRetransmission()).To(Equal(p))
		})
	})
})
