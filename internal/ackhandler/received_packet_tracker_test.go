package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Received Packet Tracker", func() {
	var (
		tracker  *receivedPacketTracker
		rttStats *utils.RTTStats
	)

	BeforeEach(func() {
		rttStats = &utils.RTTStats{}
		tracker = newReceivedPacketTracker(rttStats, utils.DefaultLogger, protocol.VersionWhatever)
	})

	Context("accepting packets", func() {
		It("saves the time when each packet arrived", func() {
			tracker.ReceivedPacket(protocol.PacketNumber(3), protocol.ECNNon, time.Now(), true)
			Expect(tracker.largestObservedReceivedTime).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
		})

		It("updates the largestObserved and the largestObservedReceivedTime", func() {
			now := time.Now()
			tracker.largestObserved = 3
			tracker.largestObservedReceivedTime = now.Add(-1 * time.Second)
			tracker.ReceivedPacket(5, protocol.ECNNon, now, true)
			Expect(tracker.largestObserved).To(Equal(protocol.PacketNumber(5)))
			Expect(tracker.largestObservedReceivedTime).To(Equal(now))
		})

		It("doesn't update the largestObserved and the largestObservedReceivedTime for a belated packet", func() {
			now := time.Now()
			timestamp := now.Add(-1 * time.Second)
			tracker.largestObserved = 5
			tracker.largestObservedReceivedTime = timestamp
			tracker.ReceivedPacket(4, protocol.ECNNon, now, true)
			Expect(tracker.largestObserved).To(Equal(protocol.PacketNumber(5)))
			Expect(tracker.largestObservedReceivedTime).To(Equal(timestamp))
		})
	})

	Context("ACKs", func() {
		Context("queueing ACKs", func() {
			receiveAndAck10Packets := func() {
				for i := 1; i <= 10; i++ {
					tracker.ReceivedPacket(protocol.PacketNumber(i), protocol.ECNNon, time.Time{}, true)
				}
				Expect(tracker.GetAckFrame(true)).ToNot(BeNil())
				Expect(tracker.ackQueued).To(BeFalse())
			}

			It("always queues an ACK for the first packet", func() {
				tracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)
				Expect(tracker.ackQueued).To(BeTrue())
				Expect(tracker.GetAlarmTimeout()).To(BeZero())
				Expect(tracker.GetAckFrame(true).DelayTime).To(BeNumerically("~", 0, time.Second))
			})

			It("works with packet number 0", func() {
				tracker.ReceivedPacket(0, protocol.ECNNon, time.Now(), true)
				Expect(tracker.ackQueued).To(BeTrue())
				Expect(tracker.GetAlarmTimeout()).To(BeZero())
				Expect(tracker.GetAckFrame(true).DelayTime).To(BeNumerically("~", 0, time.Second))
			})

			It("sets ECN flags", func() {
				tracker.ReceivedPacket(0, protocol.ECT0, time.Now(), true)
				pn := protocol.PacketNumber(1)
				for i := 0; i < 2; i++ {
					tracker.ReceivedPacket(pn, protocol.ECT1, time.Now(), true)
					pn++
				}
				for i := 0; i < 3; i++ {
					tracker.ReceivedPacket(pn, protocol.ECNCE, time.Now(), true)
					pn++
				}
				ack := tracker.GetAckFrame(false)
				Expect(ack.ECT0).To(BeEquivalentTo(1))
				Expect(ack.ECT1).To(BeEquivalentTo(2))
				Expect(ack.ECNCE).To(BeEquivalentTo(3))
			})

			It("queues an ACK for every second ack-eliciting packet", func() {
				receiveAndAck10Packets()
				p := protocol.PacketNumber(11)
				for i := 0; i <= 20; i++ {
					tracker.ReceivedPacket(p, protocol.ECNNon, time.Time{}, true)
					Expect(tracker.ackQueued).To(BeFalse())
					p++
					tracker.ReceivedPacket(p, protocol.ECNNon, time.Time{}, true)
					Expect(tracker.ackQueued).To(BeTrue())
					p++
					// dequeue the ACK frame
					Expect(tracker.GetAckFrame(true)).ToNot(BeNil())
				}
			})

			It("resets the counter when a non-queued ACK frame is generated", func() {
				receiveAndAck10Packets()
				rcvTime := time.Now()
				tracker.ReceivedPacket(11, protocol.ECNNon, rcvTime, true)
				Expect(tracker.GetAckFrame(false)).ToNot(BeNil())
				tracker.ReceivedPacket(12, protocol.ECNNon, rcvTime, true)
				Expect(tracker.GetAckFrame(true)).To(BeNil())
				tracker.ReceivedPacket(13, protocol.ECNNon, rcvTime, true)
				Expect(tracker.GetAckFrame(false)).ToNot(BeNil())
			})

			It("only sets the timer when receiving a ack-eliciting packets", func() {
				receiveAndAck10Packets()
				tracker.ReceivedPacket(11, protocol.ECNNon, time.Now(), false)
				Expect(tracker.ackQueued).To(BeFalse())
				Expect(tracker.GetAlarmTimeout()).To(BeZero())
				rcvTime := time.Now().Add(10 * time.Millisecond)
				tracker.ReceivedPacket(12, protocol.ECNNon, rcvTime, true)
				Expect(tracker.ackQueued).To(BeFalse())
				Expect(tracker.GetAlarmTimeout()).To(Equal(rcvTime.Add(protocol.MaxAckDelay)))
			})

			It("queues an ACK if it was reported missing before", func() {
				receiveAndAck10Packets()
				tracker.ReceivedPacket(11, protocol.ECNNon, time.Now(), true)
				tracker.ReceivedPacket(13, protocol.ECNNon, time.Now(), true)
				ack := tracker.GetAckFrame(true) // ACK: 1-11 and 13, missing: 12
				Expect(ack).ToNot(BeNil())
				Expect(ack.HasMissingRanges()).To(BeTrue())
				Expect(tracker.ackQueued).To(BeFalse())
				tracker.ReceivedPacket(12, protocol.ECNNon, time.Now(), true)
				Expect(tracker.ackQueued).To(BeTrue())
			})

			It("doesn't queue an ACK if it was reported missing before, but is below the threshold", func() {
				receiveAndAck10Packets()
				// 11 is missing
				tracker.ReceivedPacket(12, protocol.ECNNon, time.Now(), true)
				tracker.ReceivedPacket(13, protocol.ECNNon, time.Now(), true)
				ack := tracker.GetAckFrame(true) // ACK: 1-10, 12-13
				Expect(ack).ToNot(BeNil())
				// now receive 11
				tracker.IgnoreBelow(12)
				tracker.ReceivedPacket(11, protocol.ECNNon, time.Now(), false)
				ack = tracker.GetAckFrame(true)
				Expect(ack).To(BeNil())
			})

			It("doesn't recognize in-order packets as out-of-order after raising the threshold", func() {
				receiveAndAck10Packets()
				Expect(tracker.lastAck.LargestAcked()).To(Equal(protocol.PacketNumber(10)))
				Expect(tracker.ackQueued).To(BeFalse())
				tracker.IgnoreBelow(11)
				tracker.ReceivedPacket(11, protocol.ECNNon, time.Now(), true)
				Expect(tracker.GetAckFrame(true)).To(BeNil())
			})

			It("recognizes out-of-order packets after raising the threshold", func() {
				receiveAndAck10Packets()
				Expect(tracker.lastAck.LargestAcked()).To(Equal(protocol.PacketNumber(10)))
				Expect(tracker.ackQueued).To(BeFalse())
				tracker.IgnoreBelow(11)
				tracker.ReceivedPacket(12, protocol.ECNNon, time.Now(), true)
				ack := tracker.GetAckFrame(true)
				Expect(ack).ToNot(BeNil())
				Expect(ack.AckRanges).To(Equal([]wire.AckRange{{Smallest: 12, Largest: 12}}))
			})

			It("doesn't queue an ACK if for non-ack-eliciting packets arriving out-of-order", func() {
				receiveAndAck10Packets()
				tracker.ReceivedPacket(11, protocol.ECNNon, time.Now(), true)
				Expect(tracker.GetAckFrame(true)).To(BeNil())
				tracker.ReceivedPacket(13, protocol.ECNNon, time.Now(), false) // receive a non-ack-eliciting packet out-of-order
				Expect(tracker.GetAckFrame(true)).To(BeNil())
			})

			It("doesn't queue an ACK if packets arrive out-of-order, but haven't been acknowledged yet", func() {
				receiveAndAck10Packets()
				Expect(tracker.lastAck).ToNot(BeNil())
				tracker.ReceivedPacket(12, protocol.ECNNon, time.Now(), false)
				Expect(tracker.GetAckFrame(true)).To(BeNil())
				// 11 is received out-of-order, but this hasn't been reported in an ACK frame yet
				tracker.ReceivedPacket(11, protocol.ECNNon, time.Now(), true)
				Expect(tracker.GetAckFrame(true)).To(BeNil())
			})
		})

		Context("ACK generation", func() {
			It("generates an ACK for an ack-eliciting packet, if no ACK is queued yet", func() {
				tracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)
				// The first packet is always acknowledged.
				Expect(tracker.GetAckFrame(true)).ToNot(BeNil())
			})

			It("doesn't generate ACK for a non-ack-eliciting packet, if no ACK is queued yet", func() {
				tracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)
				// The first packet is always acknowledged.
				Expect(tracker.GetAckFrame(true)).ToNot(BeNil())

				tracker.ReceivedPacket(2, protocol.ECNNon, time.Now(), false)
				Expect(tracker.GetAckFrame(false)).To(BeNil())
				tracker.ReceivedPacket(3, protocol.ECNNon, time.Now(), true)
				ack := tracker.GetAckFrame(false)
				Expect(ack).ToNot(BeNil())
				Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
				Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(3)))
			})

			Context("for queued ACKs", func() {
				BeforeEach(func() {
					tracker.ackQueued = true
				})

				It("generates a simple ACK frame", func() {
					tracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)
					tracker.ReceivedPacket(2, protocol.ECNNon, time.Now(), true)
					ack := tracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(2)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
					Expect(ack.HasMissingRanges()).To(BeFalse())
				})

				It("generates an ACK for packet number 0", func() {
					tracker.ReceivedPacket(0, protocol.ECNNon, time.Now(), true)
					ack := tracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(0)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(0)))
					Expect(ack.HasMissingRanges()).To(BeFalse())
				})

				It("sets the delay time", func() {
					tracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)
					tracker.ReceivedPacket(2, protocol.ECNNon, time.Now().Add(-1337*time.Millisecond), true)
					ack := tracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.DelayTime).To(BeNumerically("~", 1337*time.Millisecond, 50*time.Millisecond))
				})

				It("uses a 0 delay time if the delay would be negative", func() {
					tracker.ReceivedPacket(0, protocol.ECNNon, time.Now().Add(time.Hour), true)
					ack := tracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.DelayTime).To(BeZero())
				})

				It("saves the last sent ACK", func() {
					tracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)
					ack := tracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(tracker.lastAck).To(Equal(ack))
					tracker.ReceivedPacket(2, protocol.ECNNon, time.Now(), true)
					tracker.ackQueued = true
					ack = tracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(tracker.lastAck).To(Equal(ack))
				})

				It("generates an ACK frame with missing packets", func() {
					tracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)
					tracker.ReceivedPacket(4, protocol.ECNNon, time.Now(), true)
					ack := tracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(4)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
					Expect(ack.AckRanges).To(Equal([]wire.AckRange{
						{Smallest: 4, Largest: 4},
						{Smallest: 1, Largest: 1},
					}))
				})

				It("generates an ACK for packet number 0 and other packets", func() {
					tracker.ReceivedPacket(0, protocol.ECNNon, time.Now(), true)
					tracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)
					tracker.ReceivedPacket(3, protocol.ECNNon, time.Now(), true)
					ack := tracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(3)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(0)))
					Expect(ack.AckRanges).To(Equal([]wire.AckRange{
						{Smallest: 3, Largest: 3},
						{Smallest: 0, Largest: 1},
					}))
				})

				It("doesn't add delayed packets to the packetHistory", func() {
					tracker.IgnoreBelow(7)
					tracker.ReceivedPacket(4, protocol.ECNNon, time.Now(), true)
					tracker.ReceivedPacket(10, protocol.ECNNon, time.Now(), true)
					ack := tracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(10)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(10)))
				})

				It("deletes packets from the packetHistory when a lower limit is set", func() {
					for i := 1; i <= 12; i++ {
						tracker.ReceivedPacket(protocol.PacketNumber(i), protocol.ECNNon, time.Now(), true)
					}
					tracker.IgnoreBelow(7)
					// check that the packets were deleted from the receivedPacketHistory by checking the values in an ACK frame
					ack := tracker.GetAckFrame(true)
					Expect(ack).ToNot(BeNil())
					Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(12)))
					Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(7)))
					Expect(ack.HasMissingRanges()).To(BeFalse())
				})

				It("resets all counters needed for the ACK queueing decision when sending an ACK", func() {
					tracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)
					tracker.ackAlarm = time.Now().Add(-time.Minute)
					Expect(tracker.GetAckFrame(true)).ToNot(BeNil())
					Expect(tracker.GetAlarmTimeout()).To(BeZero())
					Expect(tracker.ackElicitingPacketsReceivedSinceLastAck).To(BeZero())
					Expect(tracker.ackQueued).To(BeFalse())
				})

				It("doesn't generate an ACK when none is queued and the timer is not set", func() {
					tracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)
					tracker.ackQueued = false
					tracker.ackAlarm = time.Time{}
					Expect(tracker.GetAckFrame(true)).To(BeNil())
				})

				It("doesn't generate an ACK when none is queued and the timer has not yet expired", func() {
					tracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)
					tracker.ackQueued = false
					tracker.ackAlarm = time.Now().Add(time.Minute)
					Expect(tracker.GetAckFrame(true)).To(BeNil())
				})

				It("generates an ACK when the timer has expired", func() {
					tracker.ReceivedPacket(1, protocol.ECNNon, time.Now(), true)
					tracker.ackQueued = false
					tracker.ackAlarm = time.Now().Add(-time.Minute)
					Expect(tracker.GetAckFrame(true)).ToNot(BeNil())
				})
			})
		})
	})
})
