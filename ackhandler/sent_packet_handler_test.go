package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
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
			Expect(err).To(MatchError(errDuplicatePacketNumber))
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
			Expect(err).To(MatchError(errWrongPacketNumberIncrement))
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
			err = handler.ReceivedAck(&ack)
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
				{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1},
				{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1},
				{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1},
				{PacketNumber: 4, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1},
				{PacketNumber: 5, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1},
				{PacketNumber: 6, Frames: []frames.Frame{&streamFrame}, EntropyBit: true, Length: 1},
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
				NackRanges:      []frames.NackRange{{FirstPacketNumber: 3, LastPacketNumber: 4}},
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
				NackRanges:      []frames.NackRange{{FirstPacketNumber: 3, LastPacketNumber: 4}},
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
					{FirstPacketNumber: 4, LastPacketNumber: 4},
					{FirstPacketNumber: 2, LastPacketNumber: 2},
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
			Expect(err).To(MatchError(ErrEntropy))
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(6)))
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
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(2)))
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
					{FirstPacketNumber: 5, LastPacketNumber: 5},
					{FirstPacketNumber: 3, LastPacketNumber: 3},
				},
			}
			err := handler.ReceivedAck(&ack)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(2)))
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
				{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				{PacketNumber: 4, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				{PacketNumber: 5, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				{PacketNumber: 6, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
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
				err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
				err = handler.ReceivedAck(&ack)
				Expect(err).To(MatchError(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
			})

			It("rejects out of order ACKs", func() {
				largestObserved := 3
				ack := frames.AckFrame{
					LargestObserved: protocol.PacketNumber(largestObserved),
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
				ack.LargestObserved--
				err = handler.ReceivedAck(&ack)
				Expect(err).To(MatchError(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.LargestObserved).To(Equal(protocol.PacketNumber(largestObserved)))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(3)))
			})

			It("rejects ACKs with a too high LargestObserved packet number", func() {
				ack := frames.AckFrame{
					LargestObserved: packets[len(packets)-1].PacketNumber + 1337,
				}
				err := handler.ReceivedAck(&ack)
				Expect(err).To(MatchError(errAckForUnsentPacket))
				Expect(handler.highestInOrderAckedPacketNumber).To(Equal(protocol.PacketNumber(0)))
				Expect(handler.BytesInFlight()).To(Equal(protocol.ByteCount(6)))
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
				err := handler.ReceivedAck(&frames.AckFrame{LargestObserved: 1})
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 10*time.Minute, 1*time.Second))
				err = handler.ReceivedAck(&frames.AckFrame{LargestObserved: 2})
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
				err = handler.ReceivedAck(&frames.AckFrame{LargestObserved: 6})
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 1*time.Minute, 1*time.Second))
			})

			It("uses the DelayTime in the ack frame", func() {
				now := time.Now()
				handler.packetHistory[1].sendTime = now.Add(-10 * time.Minute)
				err := handler.ReceivedAck(&frames.AckFrame{LargestObserved: 1, DelayTime: 5 * time.Minute})
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
			})
		})
	})

	Context("Retransmission handler", func() {
		var packets []*Packet

		BeforeEach(func() {
			packets = []*Packet{
				{PacketNumber: 1, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				{PacketNumber: 2, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				{PacketNumber: 3, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				{PacketNumber: 4, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				{PacketNumber: 5, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
				{PacketNumber: 6, Frames: []frames.Frame{&streamFrame}, EntropyBit: false, Length: 1},
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
				NackRanges:      []frames.NackRange{{FirstPacketNumber: 3, LastPacketNumber: 3}},
			}
			err := handler.ReceivedAck(&ack)
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
				NackRanges:      []frames.NackRange{{FirstPacketNumber: 1, LastPacketNumber: 1}},
			}
			err = handler.ReceivedAck(&ack)
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
			err = handler.ReceivedAck(&ack)
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
			err := handler.ReceivedAck(&frames.AckFrame{
				LargestObserved: 3,
				NackRanges:      []frames.NackRange{{2, 2}},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(cong.nCalls).To(Equal(4)) // 3 * SentPacket + 1 * ReceivedAck
			// rttUpdated, bytesInFlight, ackedPackets, lostPackets
			Expect(cong.argsOnCongestionEvent[0]).To(BeTrue())
			Expect(cong.argsOnCongestionEvent[1]).To(Equal(protocol.ByteCount(2)))
			Expect(cong.argsOnCongestionEvent[2]).To(Equal(congestion.PacketVector{{1, 1}, {3, 3}}))
			Expect(cong.argsOnCongestionEvent[3]).To(BeEmpty())

			// Loose the packet
			handler.SentPacket(&Packet{PacketNumber: 4, Frames: []frames.Frame{}, Length: 4})
			err = handler.ReceivedAck(&frames.AckFrame{
				LargestObserved: 4,
				NackRanges:      []frames.NackRange{{2, 2}},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(cong.argsOnCongestionEvent[2]).To(Equal(congestion.PacketVector{{4, 4}}))
			Expect(cong.argsOnCongestionEvent[3]).To(Equal(congestion.PacketVector{{2, 2}}))
		})

		It("allows or denies sending", func() {
			Expect(handler.AllowsSending()).To(BeTrue())
			err := handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: protocol.DefaultTCPMSS + 1})
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.AllowsSending()).To(BeFalse())
		})

		It("should call OnRetransmissionTimeout", func() {
			err := handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
			Expect(err).NotTo(HaveOccurred())
			handler.packetHistory[1].rtoTime = time.Now().Add(-time.Second)
			handler.queuePacketsRTO()
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

		It("stores RTO in sent packets", func() {
			handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
			val := handler.packetHistory[1].rtoTime
			expected := time.Now().Add(protocol.DefaultRetransmissionTime)
			Expect(utils.AbsDuration(expected.Sub(val))).To(BeNumerically("<", time.Millisecond))
		})
	})

	Context("RTO retransmission", func() {
		Context("calculating the time to first RTO", func() {
			It("defaults to inf", func() {
				Expect(handler.TimeToFirstRTO()).To(Equal(utils.InfDuration))
			})

			It("returns time to RTO", func() {
				err := handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.TimeToFirstRTO()).To(BeNumerically("~", protocol.DefaultRetransmissionTime, time.Millisecond))
			})

			It("returns 0 when RTOs are required", func() {
				err := handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
				Expect(err).NotTo(HaveOccurred())
				handler.packetHistory[1].rtoTime = time.Now().Add(-time.Second)
				Expect(handler.TimeToFirstRTO()).To(BeZero())
			})

			It("ignores nil packets", func() {
				handler.packetHistory[1] = nil
				handler.queuePacketsRTO()
				Expect(handler.TimeToFirstRTO()).To(Equal(utils.InfDuration))
			})
		})

		Context("queuing packets due to RTO", func() {
			It("does nothing if not required", func() {
				err := handler.SentPacket(&Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
				Expect(err).NotTo(HaveOccurred())
				handler.queuePacketsRTO()
				Expect(handler.retransmissionQueue).To(BeEmpty())
			})

			It("queues a packet if RTO expired", func() {
				p := &Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1}
				err := handler.SentPacket(p)
				Expect(err).NotTo(HaveOccurred())
				handler.packetHistory[1].rtoTime = time.Now().Add(-time.Second)
				handler.queuePacketsRTO()
				Expect(handler.retransmissionQueue).To(HaveLen(1))
				Expect(handler.retransmissionQueue[0]).To(Equal(p))
			})

			It("does not queue retransmittedpackets", func() {
				p := &Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1, Retransmitted: true}
				err := handler.SentPacket(p)
				Expect(err).NotTo(HaveOccurred())
				handler.packetHistory[1].rtoTime = time.Now().Add(-time.Second)
				handler.queuePacketsRTO()
				Expect(handler.retransmissionQueue).To(BeEmpty())
			})

			It("ignores nil packets", func() {
				handler.packetHistory[1] = nil
				handler.queuePacketsRTO()
				Expect(handler.retransmissionQueue).To(BeEmpty())
			})
		})

		It("works with HasPacketForRetransmission", func() {
			p := &Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1}
			err := handler.SentPacket(p)
			Expect(err).NotTo(HaveOccurred())
			handler.packetHistory[1].rtoTime = time.Now().Add(-time.Second)
			Expect(handler.HasPacketForRetransmission()).To(BeTrue())
		})

		It("works with DequeuePacketForRetransmission", func() {
			p := &Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1}
			err := handler.SentPacket(p)
			Expect(err).NotTo(HaveOccurred())
			handler.packetHistory[1].rtoTime = time.Now().Add(-time.Second)
			Expect(handler.DequeuePacketForRetransmission()).To(Equal(p))
		})
	})
})
