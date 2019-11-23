package ackhandler

import (
	"fmt"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SentPacketHandler", func() {
	var (
		handler     *sentPacketHandler
		streamFrame wire.StreamFrame
		lostPackets []protocol.PacketNumber
	)

	BeforeEach(func() {
		lostPackets = nil
		rttStats := &congestion.RTTStats{}
		handler = NewSentPacketHandler(42, rttStats, nil, utils.DefaultLogger).(*sentPacketHandler)
		streamFrame = wire.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}
	})

	getPacket := func(pn protocol.PacketNumber, encLevel protocol.EncryptionLevel) *Packet {
		if el, ok := handler.getPacketNumberSpace(encLevel).history.packetMap[pn]; ok {
			return &el.Value
		}
		return nil
	}

	ackElicitingPacket := func(p *Packet) *Packet {
		if p.EncryptionLevel == protocol.EncryptionUnspecified {
			p.EncryptionLevel = protocol.Encryption1RTT
		}
		if p.Length == 0 {
			p.Length = 1
		}
		if p.SendTime.IsZero() {
			p.SendTime = time.Now()
		}
		if len(p.Frames) == 0 {
			p.Frames = []Frame{
				{Frame: &wire.PingFrame{}, OnLost: func(wire.Frame) { lostPackets = append(lostPackets, p.PacketNumber) }},
			}
		}
		return p
	}

	nonAckElicitingPacket := func(p *Packet) *Packet {
		p = ackElicitingPacket(p)
		p.Frames = nil
		p.LargestAcked = 1
		return p
	}

	cryptoPacket := func(p *Packet) *Packet {
		p = ackElicitingPacket(p)
		p.EncryptionLevel = protocol.EncryptionInitial
		return p
	}

	expectInPacketHistory := func(expected []protocol.PacketNumber, encLevel protocol.EncryptionLevel) {
		pnSpace := handler.getPacketNumberSpace(encLevel)
		ExpectWithOffset(1, pnSpace.history.Len()).To(Equal(len(expected)))
		for _, p := range expected {
			ExpectWithOffset(2, pnSpace.history.packetMap).To(HaveKey(p))
		}
	}

	updateRTT := func(rtt time.Duration) {
		handler.rttStats.UpdateRTT(rtt, 0, time.Now())
		ExpectWithOffset(1, handler.rttStats.SmoothedRTT()).To(Equal(rtt))
	}

	Context("registering sent packets", func() {
		It("accepts two consecutive packets", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, EncryptionLevel: protocol.EncryptionHandshake}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, EncryptionLevel: protocol.EncryptionHandshake}))
			Expect(handler.handshakePackets.largestSent).To(Equal(protocol.PacketNumber(2)))
			expectInPacketHistory([]protocol.PacketNumber{1, 2}, protocol.EncryptionHandshake)
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))
		})

		It("accepts packet number 0", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 0, EncryptionLevel: protocol.Encryption1RTT}))
			Expect(handler.oneRTTPackets.largestSent).To(BeZero())
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, EncryptionLevel: protocol.Encryption1RTT}))
			Expect(handler.oneRTTPackets.largestSent).To(Equal(protocol.PacketNumber(1)))
			expectInPacketHistory([]protocol.PacketNumber{0, 1}, protocol.Encryption1RTT)
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))
		})

		It("stores the sent time", func() {
			sendTime := time.Now().Add(-time.Minute)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: sendTime}))
			Expect(handler.oneRTTPackets.lastSentAckElicitingPacketTime).To(Equal(sendTime))
		})

		It("stores the sent time of Initial packets", func() {
			sendTime := time.Now().Add(-time.Minute)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: sendTime, EncryptionLevel: protocol.EncryptionInitial}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, SendTime: sendTime.Add(time.Hour), EncryptionLevel: protocol.Encryption1RTT}))
			Expect(handler.initialPackets.lastSentAckElicitingPacketTime).To(Equal(sendTime))
		})

		It("does not store non-ack-eliciting packets", func() {
			handler.SentPacket(nonAckElicitingPacket(&Packet{PacketNumber: 1}))
			Expect(handler.oneRTTPackets.history.Len()).To(BeZero())
			Expect(handler.oneRTTPackets.lastSentAckElicitingPacketTime).To(BeZero())
			Expect(handler.bytesInFlight).To(BeZero())
		})
	})

	Context("ACK processing", func() {
		BeforeEach(func() {
			for i := protocol.PacketNumber(0); i < 10; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: i}))
			}
			// Increase RTT, because the tests would be flaky otherwise
			updateRTT(time.Hour)
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(10)))
		})

		Context("ACK validation", func() {
			It("accepts ACKs sent in packet 0", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 5}}}
				err := handler.ReceivedAck(ack, 0, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.oneRTTPackets.largestAcked).To(Equal(protocol.PacketNumber(5)))
			})

			It("accepts multiple ACKs sent in the same packet", func() {
				ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 3}}}
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 4}}}
				Expect(handler.ReceivedAck(ack1, 1337, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(handler.oneRTTPackets.largestAcked).To(Equal(protocol.PacketNumber(3)))
				// this wouldn't happen in practice
				// for testing purposes, we pretend send a different ACK frame in a duplicated packet, to be able to verify that it actually doesn't get processed
				Expect(handler.ReceivedAck(ack2, 1337, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(handler.oneRTTPackets.largestAcked).To(Equal(protocol.PacketNumber(4)))
			})

			It("rejects ACKs with a too high LargestAcked packet number", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 9999}}}
				err := handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())
				Expect(err).To(MatchError("PROTOCOL_VIOLATION: Received ACK for an unsent packet"))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(10)))
			})

			It("ignores repeated ACKs", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 3}}}
				Expect(handler.ReceivedAck(ack, 1337, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(6)))
				Expect(handler.ReceivedAck(ack, 1337+1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(handler.oneRTTPackets.largestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(6)))
			})
		})

		Context("acks the right packets", func() {
			expectInPacketHistoryOrLost := func(expected []protocol.PacketNumber, encLevel protocol.EncryptionLevel) {
				pnSpace := handler.getPacketNumberSpace(encLevel)
				ExpectWithOffset(1, pnSpace.history.Len()+len(lostPackets)).To(Equal(len(expected)))
			expectedLoop:
				for _, p := range expected {
					if _, ok := pnSpace.history.packetMap[p]; ok {
						continue
					}
					for _, lostP := range lostPackets {
						if lostP == p {
							continue expectedLoop
						}
					}
					Fail(fmt.Sprintf("Packet %d not in packet history.", p))
				}
			}

			It("adjusts the LargestAcked, and adjusts the bytes in flight", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 5}}}
				Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(handler.oneRTTPackets.largestAcked).To(Equal(protocol.PacketNumber(5)))
				expectInPacketHistoryOrLost([]protocol.PacketNumber{6, 7, 8, 9}, protocol.Encryption1RTT)
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(4)))
			})

			It("acks packet 0", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}
				Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(getPacket(0, protocol.Encryption1RTT)).To(BeNil())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{1, 2, 3, 4, 5, 6, 7, 8, 9}, protocol.Encryption1RTT)
			})

			It("calls the OnAcked callback", func() {
				var acked bool
				ping := &wire.PingFrame{}
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber: 13,
					Frames: []Frame{{Frame: ping, OnAcked: func(f wire.Frame) {
						Expect(f).To(Equal(ping))
						acked = true
					},
					}},
				}))
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 13}}}
				Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(acked).To(BeTrue())
			})

			It("handles an ACK frame with one missing packet range", func() {
				ack := &wire.AckFrame{ // lose 4 and 5
					AckRanges: []wire.AckRange{
						{Smallest: 6, Largest: 9},
						{Smallest: 1, Largest: 3},
					},
				}
				Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 4, 5}, protocol.Encryption1RTT)
			})

			It("does not ack packets below the LowestAcked", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 3, Largest: 8}}}
				Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 1, 2, 9}, protocol.Encryption1RTT)
			})

			It("handles an ACK with multiple missing packet ranges", func() {
				ack := &wire.AckFrame{ // packets 2, 4 and 5, and 8 were lost
					AckRanges: []wire.AckRange{
						{Smallest: 9, Largest: 9},
						{Smallest: 6, Largest: 7},
						{Smallest: 3, Largest: 3},
						{Smallest: 1, Largest: 1},
					},
				}
				Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 2, 4, 5, 8}, protocol.Encryption1RTT)
			})

			It("processes an ACK frame that would be sent after a late arrival of a packet", func() {
				ack1 := &wire.AckFrame{ // 5 lost
					AckRanges: []wire.AckRange{
						{Smallest: 6, Largest: 6},
						{Smallest: 1, Largest: 4},
					},
				}
				Expect(handler.ReceivedAck(ack1, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 5, 7, 8, 9}, protocol.Encryption1RTT)
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 6}}} // now ack 5
				Expect(handler.ReceivedAck(ack2, 2, protocol.Encryption1RTT, time.Now())).To(Succeed())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 7, 8, 9}, protocol.Encryption1RTT)
			})

			It("processes an ACK that contains old ACK ranges", func() {
				ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 6}}}
				Expect(handler.ReceivedAck(ack1, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 7, 8, 9}, protocol.Encryption1RTT)
				ack2 := &wire.AckFrame{
					AckRanges: []wire.AckRange{
						{Smallest: 8, Largest: 8},
						{Smallest: 3, Largest: 3},
						{Smallest: 1, Largest: 1},
					},
				}
				Expect(handler.ReceivedAck(ack2, 2, protocol.Encryption1RTT, time.Now())).To(Succeed())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 7, 9}, protocol.Encryption1RTT)
			})
		})

		Context("calculating RTT", func() {
			It("computes the RTT", func() {
				now := time.Now()
				// First, fake the sent times of the first, second and last packet
				getPacket(1, protocol.Encryption1RTT).SendTime = now.Add(-10 * time.Minute)
				getPacket(2, protocol.Encryption1RTT).SendTime = now.Add(-5 * time.Minute)
				getPacket(6, protocol.Encryption1RTT).SendTime = now.Add(-1 * time.Minute)
				// Now, check that the proper times are used when calculating the deltas
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
				err := handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 10*time.Minute, 1*time.Second))
				ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 2}}}
				err = handler.ReceivedAck(ack, 2, protocol.Encryption1RTT, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
				ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 6}}}
				err = handler.ReceivedAck(ack, 3, protocol.Encryption1RTT, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 1*time.Minute, 1*time.Second))
			})

			It("ignores the DelayTime for Initial and Handshake packets", func() {
				handler.SentPacket(cryptoPacket(&Packet{PacketNumber: 1}))
				handler.rttStats.SetMaxAckDelay(time.Hour)
				// make sure the rttStats have a min RTT, so that the delay is used
				handler.rttStats.UpdateRTT(5*time.Minute, 0, time.Now())
				getPacket(1, protocol.EncryptionInitial).SendTime = time.Now().Add(-10 * time.Minute)
				ack := &wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}},
					DelayTime: 5 * time.Minute,
				}
				Expect(handler.ReceivedAck(ack, 1, protocol.EncryptionInitial, time.Now())).To(Succeed())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 10*time.Minute, 1*time.Second))
			})

			It("uses the DelayTime in the ACK frame", func() {
				handler.rttStats.SetMaxAckDelay(time.Hour)
				// make sure the rttStats have a min RTT, so that the delay is used
				handler.rttStats.UpdateRTT(5*time.Minute, 0, time.Now())
				getPacket(1, protocol.Encryption1RTT).SendTime = time.Now().Add(-10 * time.Minute)
				ack := &wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}},
					DelayTime: 5 * time.Minute,
				}
				Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
			})

			It("limits the DelayTime in the ACK frame to max_ack_delay", func() {
				handler.rttStats.SetMaxAckDelay(time.Minute)
				// make sure the rttStats have a min RTT, so that the delay is used
				handler.rttStats.UpdateRTT(5*time.Minute, 0, time.Now())
				getPacket(1, protocol.Encryption1RTT).SendTime = time.Now().Add(-10 * time.Minute)
				ack := &wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}},
					DelayTime: 5 * time.Minute,
				}
				Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 9*time.Minute, 1*time.Second))
			})
		})

		Context("determining which ACKs we have received an ACK for", func() {
			BeforeEach(func() {
				morePackets := []*Packet{
					{
						PacketNumber:    13,
						LargestAcked:    100,
						Frames:          []Frame{{Frame: &streamFrame, OnLost: func(wire.Frame) {}}},
						Length:          1,
						EncryptionLevel: protocol.Encryption1RTT,
					},
					{
						PacketNumber:    14,
						LargestAcked:    200,
						Frames:          []Frame{{Frame: &streamFrame, OnLost: func(wire.Frame) {}}},
						Length:          1,
						EncryptionLevel: protocol.Encryption1RTT,
					},
					{
						PacketNumber:    15,
						Frames:          []Frame{{Frame: &streamFrame, OnLost: func(wire.Frame) {}}},
						Length:          1,
						EncryptionLevel: protocol.Encryption1RTT,
					},
				}
				for _, packet := range morePackets {
					handler.SentPacket(packet)
				}
			})

			It("determines which ACK we have received an ACK for", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 15}}}
				Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(201)))
			})

			It("doesn't do anything when the acked packet didn't contain an ACK", func() {
				ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 13}}}
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 15, Largest: 15}}}
				Expect(handler.ReceivedAck(ack1, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(101)))
				Expect(handler.ReceivedAck(ack2, 2, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(101)))
			})

			It("doesn't decrease the value", func() {
				ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 14, Largest: 14}}}
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 13}}}
				Expect(handler.ReceivedAck(ack1, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(201)))
				Expect(handler.ReceivedAck(ack2, 2, protocol.Encryption1RTT, time.Now())).To(Succeed())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(201)))
			})
		})
	})

	Context("congestion", func() {
		var cong *mocks.MockSendAlgorithmWithDebugInfos

		BeforeEach(func() {
			cong = mocks.NewMockSendAlgorithmWithDebugInfos(mockCtrl)
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
			handler.SentPacket(&Packet{
				PacketNumber:    1,
				Length:          42,
				Frames:          []Frame{{Frame: &wire.PingFrame{}, OnLost: func(wire.Frame) {}}},
				EncryptionLevel: protocol.Encryption1RTT,
			})
		})

		It("should call MaybeExitSlowStart and OnPacketAcked", func() {
			rcvTime := time.Now().Add(-5 * time.Second)
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3)
			cong.EXPECT().TimeUntilSend(gomock.Any()).Times(3)
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(), // must be called before packets are acked
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(3), rcvTime),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(3), rcvTime),
			)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 3}))
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 2}}}
			err := handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, rcvTime)
			Expect(err).NotTo(HaveOccurred())
		})

		It("doesn't call OnPacketAcked when a retransmitted packet is acked", func() {
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
			cong.EXPECT().TimeUntilSend(gomock.Any()).Times(2)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2}))
			// lose packet 1
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(2), gomock.Any()),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(2)),
			)
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			err := handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())
			Expect(err).ToNot(HaveOccurred())
			// don't EXPECT any further calls to the congestion controller
			ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 2}}}
			err = handler.ReceivedAck(ack, 2, protocol.Encryption1RTT, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})

		It("calls OnPacketAcked and OnPacketLost with the right bytes_in_flight value", func() {
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(4)
			cong.EXPECT().TimeUntilSend(gomock.Any()).Times(4)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, SendTime: time.Now().Add(-30 * time.Minute)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 3, SendTime: time.Now().Add(-30 * time.Minute)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 4, SendTime: time.Now()}))
			// receive the first ACK
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(4), gomock.Any()),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(4)),
			)
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			err := handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now().Add(-30*time.Minute))
			Expect(err).ToNot(HaveOccurred())
			// receive the second ACK
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(4), protocol.ByteCount(1), protocol.ByteCount(2), gomock.Any()),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(3), protocol.ByteCount(1), protocol.ByteCount(2)),
			)
			ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 4, Largest: 4}}}
			err = handler.ReceivedAck(ack, 2, protocol.Encryption1RTT, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})

		It("passes the bytes in flight to CanSend", func() {
			handler.bytesInFlight = 42
			cong.EXPECT().CanSend(protocol.ByteCount(42))
			handler.SendMode()
		})

		It("allows sending of ACKs when congestion limited", func() {
			cong.EXPECT().CanSend(gomock.Any()).Return(true)
			Expect(handler.SendMode()).To(Equal(SendAny))
			cong.EXPECT().CanSend(gomock.Any()).Return(false)
			Expect(handler.SendMode()).To(Equal(SendAck))
		})

		It("allows sending of ACKs when we're keeping track of MaxOutstandingSentPackets packets", func() {
			cong.EXPECT().CanSend(gomock.Any()).Return(true).AnyTimes()
			cong.EXPECT().TimeUntilSend(gomock.Any()).AnyTimes()
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			for i := protocol.PacketNumber(1); i < protocol.MaxOutstandingSentPackets; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: i}))
				Expect(handler.SendMode()).To(Equal(SendAny))
			}
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: protocol.MaxOutstandingSentPackets}))
			Expect(handler.SendMode()).To(Equal(SendAck))
		})

		It("allows PTOs, even when congestion limited", func() {
			// note that we don't EXPECT a call to GetCongestionWindow
			// that means retransmissions are sent without considering the congestion window
			handler.numProbesToSend = 1
			handler.ptoMode = SendPTOHandshake
			Expect(handler.SendMode()).To(Equal(SendPTOHandshake))
		})

		It("gets the pacing delay", func() {
			sendTime := time.Now().Add(-time.Minute)
			handler.bytesInFlight = 100
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			cong.EXPECT().TimeUntilSend(protocol.ByteCount(100)).Return(time.Hour)
			handler.SentPacket(&Packet{PacketNumber: 1, SendTime: sendTime, EncryptionLevel: protocol.Encryption1RTT})
			Expect(handler.TimeUntilSend()).To(Equal(sendTime.Add(time.Hour)))
		})

		It("allows sending of all RTO probe packets", func() {
			handler.numProbesToSend = 5
			Expect(handler.ShouldSendNumPackets()).To(Equal(5))
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

	It("doesn't set an alarm if there are no outstanding packets", func() {
		handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 10}))
		handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 11}))
		ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 10, Largest: 11}}}
		err := handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())
		Expect(err).ToNot(HaveOccurred())
		Expect(handler.GetLossDetectionTimeout()).To(BeZero())
	})

	It("does nothing on OnAlarm if there are no outstanding packets", func() {
		Expect(handler.OnLossDetectionTimeout()).To(Succeed())
		Expect(handler.SendMode()).To(Equal(SendAny))
	})

	Context("probe packets", func() {
		It("queues a probe packet", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 10}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 11}))
			queued := handler.QueueProbePacket(protocol.Encryption1RTT)
			Expect(queued).To(BeTrue())
			Expect(lostPackets).To(Equal([]protocol.PacketNumber{10}))
		})

		It("says when it can't queue a probe packet", func() {
			queued := handler.QueueProbePacket(protocol.Encryption1RTT)
			Expect(queued).To(BeFalse())
		})

		It("implements exponential backoff", func() {
			handler.SetHandshakeComplete()
			sendTime := time.Now().Add(-time.Hour)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: sendTime}))
			timeout := handler.GetLossDetectionTimeout().Sub(sendTime)
			Expect(handler.GetLossDetectionTimeout().Sub(sendTime)).To(Equal(timeout))
			handler.ptoCount = 1
			handler.setLossDetectionTimer()
			Expect(handler.GetLossDetectionTimeout().Sub(sendTime)).To(Equal(2 * timeout))
			handler.ptoCount = 2
			handler.setLossDetectionTimer()
			Expect(handler.GetLossDetectionTimeout().Sub(sendTime)).To(Equal(4 * timeout))
		})

		It("resets the PTO mode when a packet number space is dropped", func() {
			now := time.Now()
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber:    1,
				EncryptionLevel: protocol.EncryptionHandshake,
				SendTime:        now.Add(-2 * time.Hour),
			}))
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber: 2,
				SendTime:     now.Add(-time.Hour),
			}))
			// PTO timer based on the Handshake packet
			Expect(handler.GetLossDetectionTimeout()).To(BeTemporally("~", now.Add(-2*time.Hour), time.Second))
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOHandshake))
			handler.SetHandshakeComplete()
			handler.DropPackets(protocol.EncryptionHandshake)
			// PTO timer based on the 1-RTT packet
			Expect(handler.GetLossDetectionTimeout()).To(BeTemporally("~", now.Add(-time.Hour), time.Second))
			Expect(handler.SendMode()).ToNot(Equal(SendPTOHandshake))
		})

		It("allows two 1-RTT PTOs", func() {
			handler.SetHandshakeComplete()
			var lostPackets []protocol.PacketNumber
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber: 1,
				SendTime:     time.Now().Add(-time.Hour),
				Frames: []Frame{
					{Frame: &wire.PingFrame{}, OnLost: func(wire.Frame) { lostPackets = append(lostPackets, 1) }},
				},
			}))
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			Expect(handler.ShouldSendNumPackets()).To(Equal(2))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2}))
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 3}))
			Expect(handler.SendMode()).ToNot(Equal(SendPTOAppData))
		})

		It("only counts ack-eliciting packets as probe packets", func() {
			handler.SetHandshakeComplete()
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			Expect(handler.ShouldSendNumPackets()).To(Equal(2))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2}))
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			for p := protocol.PacketNumber(3); p < 30; p++ {
				handler.SentPacket(nonAckElicitingPacket(&Packet{PacketNumber: p}))
				Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			}
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 30}))
			Expect(handler.SendMode()).ToNot(Equal(SendPTOAppData))
		})

		It("gets two probe packets if RTO expires", func() {
			handler.SetHandshakeComplete()
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2}))

			updateRTT(time.Hour)
			Expect(handler.oneRTTPackets.lossTime.IsZero()).To(BeTrue())

			Expect(handler.OnLossDetectionTimeout()).To(Succeed()) // TLP
			Expect(handler.ptoCount).To(BeEquivalentTo(1))
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 3}))
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 4}))

			Expect(handler.OnLossDetectionTimeout()).To(Succeed()) // PTO
			Expect(handler.ptoCount).To(BeEquivalentTo(2))
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 5}))
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 6}))

			Expect(handler.SendMode()).To(Equal(SendAny))
		})

		It("gets two probe packets if PTO expires, for Handshake packets", func() {
			handler.SentPacket(cryptoPacket(&Packet{PacketNumber: 1}))
			handler.SentPacket(cryptoPacket(&Packet{PacketNumber: 2}))

			updateRTT(time.Hour)
			Expect(handler.initialPackets.lossTime.IsZero()).To(BeTrue())

			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOInitial))
			handler.SentPacket(cryptoPacket(&Packet{PacketNumber: 3}))
			Expect(handler.SendMode()).To(Equal(SendPTOInitial))
			handler.SentPacket(cryptoPacket(&Packet{PacketNumber: 3}))

			Expect(handler.SendMode()).To(Equal(SendAny))
		})

		It("doesn't send 1-RTT probe packets before the handshake completes", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1}))
			updateRTT(time.Hour)
			Expect(handler.OnLossDetectionTimeout()).To(Succeed()) // TLP
			Expect(handler.GetLossDetectionTimeout()).To(BeZero())
			Expect(handler.SendMode()).To(Equal(SendAny))
			handler.SetHandshakeComplete()
			Expect(handler.GetLossDetectionTimeout()).ToNot(BeZero())
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
		})

		It("resets the send mode when it receives an acknowledgement after queueing probe packets", func() {
			handler.SetHandshakeComplete()
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.rttStats.UpdateRTT(time.Second, 0, time.Now())
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
			Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendAny))
		})

		It("handles ACKs for the original packet", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 5, SendTime: time.Now().Add(-time.Hour)}))
			handler.rttStats.UpdateRTT(time.Second, 0, time.Now())
			err := handler.OnLossDetectionTimeout()
			Expect(err).ToNot(HaveOccurred())
			err = handler.OnLossDetectionTimeout()
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("Packet-based loss detection", func() {
		It("declares packet below the packet loss threshold as lost", func() {
			for i := protocol.PacketNumber(1); i <= 6; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: i}))
			}
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 6, Largest: 6}}}
			Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, time.Now())).To(Succeed())
			expectInPacketHistory([]protocol.PacketNumber{4, 5}, protocol.Encryption1RTT)
			Expect(lostPackets).To(Equal([]protocol.PacketNumber{1, 2, 3}))
		})
	})

	Context("Delay-based loss detection", func() {
		It("immediately detects old packets as lost when receiving an ACK", func() {
			now := time.Now()
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: now.Add(-time.Hour)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, SendTime: now.Add(-time.Second)}))
			Expect(handler.oneRTTPackets.lossTime.IsZero()).To(BeTrue())

			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, now)).To(Succeed())
			// no need to set an alarm, since packet 1 was already declared lost
			Expect(handler.oneRTTPackets.lossTime.IsZero()).To(BeTrue())
			Expect(handler.bytesInFlight).To(BeZero())
		})

		It("sets the early retransmit alarm", func() {
			now := time.Now()
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: now.Add(-2 * time.Second)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, SendTime: now.Add(-2 * time.Second)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 3, SendTime: now.Add(-time.Second)}))
			Expect(handler.oneRTTPackets.lossTime.IsZero()).To(BeTrue())

			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			Expect(handler.ReceivedAck(ack, 1, protocol.Encryption1RTT, now.Add(-time.Second))).To(Succeed())
			Expect(handler.rttStats.SmoothedRTT()).To(Equal(time.Second))

			// Packet 1 should be considered lost (1+1/8) RTTs after it was sent.
			Expect(handler.oneRTTPackets.lossTime.IsZero()).To(BeFalse())
			Expect(handler.oneRTTPackets.lossTime.Sub(getPacket(1, protocol.Encryption1RTT).SendTime)).To(Equal(time.Second * 9 / 8))
		})

		It("sets the early retransmit alarm for crypto packets", func() {
			now := time.Now()
			handler.SentPacket(cryptoPacket(&Packet{PacketNumber: 1, SendTime: now.Add(-2 * time.Second)}))
			handler.SentPacket(cryptoPacket(&Packet{PacketNumber: 2, SendTime: now.Add(-2 * time.Second)}))
			handler.SentPacket(cryptoPacket(&Packet{PacketNumber: 3, SendTime: now.Add(-time.Second)}))
			Expect(handler.initialPackets.lossTime.IsZero()).To(BeTrue())

			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			Expect(handler.ReceivedAck(ack, 1, protocol.EncryptionInitial, now.Add(-time.Second))).To(Succeed())
			Expect(handler.rttStats.SmoothedRTT()).To(Equal(time.Second))

			// Packet 1 should be considered lost (1+1/8) RTTs after it was sent.
			Expect(handler.initialPackets.lossTime.IsZero()).To(BeFalse())
			Expect(handler.initialPackets.lossTime.Sub(getPacket(1, protocol.EncryptionInitial).SendTime)).To(Equal(time.Second * 9 / 8))
		})
	})

	Context("crypto packets", func() {
		It("rejects an ACK that acks packets with a higher encryption level", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber:    13,
				EncryptionLevel: protocol.Encryption1RTT,
			}))
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 13}}}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionHandshake, time.Now())
			Expect(err).To(MatchError("PROTOCOL_VIOLATION: Received ACK for an unsent packet"))
		})

		It("deletes Initial packets", func() {
			for i := protocol.PacketNumber(0); i < 6; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber:    i,
					EncryptionLevel: protocol.EncryptionInitial,
				}))
			}
			for i := protocol.PacketNumber(0); i < 10; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber:    i,
					EncryptionLevel: protocol.EncryptionHandshake,
				}))
			}
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(16)))
			handler.DropPackets(protocol.EncryptionInitial)
			Expect(lostPackets).To(BeEmpty()) // frames must not be queued for retransmission
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(10)))
			Expect(handler.initialPackets).To(BeNil())
			Expect(handler.handshakePackets.history.Len()).ToNot(BeZero())
		})

		It("deletes Handshake packets", func() {
			for i := protocol.PacketNumber(0); i < 6; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber:    i,
					EncryptionLevel: protocol.EncryptionHandshake,
				}))
			}
			for i := protocol.PacketNumber(0); i < 10; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber:    i,
					EncryptionLevel: protocol.Encryption1RTT,
				}))
			}
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(16)))
			handler.DropPackets(protocol.EncryptionHandshake)
			Expect(lostPackets).To(BeEmpty()) // frames must not be queued for retransmission
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(10)))
			Expect(handler.handshakePackets).To(BeNil())
		})
	})

	Context("peeking and popping packet number", func() {
		It("peeks and pops the initial packet number", func() {
			pn, _ := handler.PeekPacketNumber(protocol.EncryptionInitial)
			Expect(pn).To(Equal(protocol.PacketNumber(42)))
			Expect(handler.PopPacketNumber(protocol.EncryptionInitial)).To(Equal(protocol.PacketNumber(42)))
		})

		It("peeks and pops beyond the initial packet number", func() {
			Expect(handler.PopPacketNumber(protocol.EncryptionInitial)).To(Equal(protocol.PacketNumber(42)))
			Expect(handler.PopPacketNumber(protocol.EncryptionInitial)).To(BeNumerically(">", 42))
		})

		It("starts at 0 for handshake and application-data packet number space", func() {
			pn, _ := handler.PeekPacketNumber(protocol.EncryptionHandshake)
			Expect(pn).To(BeZero())
			Expect(handler.PopPacketNumber(protocol.EncryptionHandshake)).To(BeZero())
			pn, _ = handler.PeekPacketNumber(protocol.Encryption1RTT)
			Expect(pn).To(BeZero())
			Expect(handler.PopPacketNumber(protocol.Encryption1RTT)).To(BeZero())
		})
	})

	Context("resetting for retry", func() {
		It("queues outstanding packets for retransmission and cancels alarms", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 42, EncryptionLevel: protocol.EncryptionInitial}))
			Expect(handler.GetLossDetectionTimeout()).ToNot(BeZero())
			Expect(handler.bytesInFlight).ToNot(BeZero())
			Expect(handler.SendMode()).To(Equal(SendAny))
			// now receive a Retry
			Expect(handler.ResetForRetry()).To(Succeed())
			Expect(lostPackets).To(Equal([]protocol.PacketNumber{42}))
			Expect(handler.bytesInFlight).To(BeZero())
			Expect(handler.GetLossDetectionTimeout()).To(BeZero())
			Expect(handler.SendMode()).To(Equal(SendAny))
		})
	})
})
