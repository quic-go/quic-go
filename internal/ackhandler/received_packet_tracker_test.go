package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Received Packet Tracker", func() {
	var (
		tracker  *receivedPacketTracker
		rttStats *congestion.RTTStats
	)

	BeforeEach(func() {
		rttStats = &congestion.RTTStats{}
		tracker = newReceivedPacketTracker(rttStats, utils.DefaultLogger, protocol.VersionWhatever)
	})

	Context("accepting packets", func() {
		It("saves the time when each packet arrived", func() {
			tracker.ReceivedPacket(protocol.PacketNumber(3), time.Now(), true)
			Expect(tracker.largestObservedReceivedTime).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
		})

		It("updates the largestObserved and the largestObservedReceivedTime", func() {
			now := time.Now()
			tracker.largestObserved = 3
			tracker.largestObservedReceivedTime = now.Add(-1 * time.Second)
			tracker.ReceivedPacket(5, now, true)
			Expect(tracker.largestObserved).To(Equal(protocol.PacketNumber(5)))
			Expect(tracker.largestObservedReceivedTime).To(Equal(now))
		})

		It("doesn't update the largestObserved and the largestObservedReceivedTime for a belated packet", func() {
			now := time.Now()
			timestamp := now.Add(-1 * time.Second)
			tracker.largestObserved = 5
			tracker.largestObservedReceivedTime = timestamp
			tracker.ReceivedPacket(4, now, true)
			Expect(tracker.largestObserved).To(Equal(protocol.PacketNumber(5)))
			Expect(tracker.largestObservedReceivedTime).To(Equal(timestamp))
		})
	})

	Context("ACKs", func() {
		Context("queueing ACKs", func() {
			receiveAndAck10Packets := func() {
				for i := 1; i <= 10; i++ {
					tracker.ReceivedPacket(protocol.PacketNumber(i), time.Time{}, true)
				}
				Expect(tracker.GetAckFrame()).ToNot(BeNil())
				Expect(tracker.ackQueued).To(BeFalse())
			}

			receiveAndAckPacketsUntilAckDecimation := func() {
				for i := 1; i <= minReceivedBeforeAckDecimation; i++ {
					tracker.ReceivedPacket(protocol.PacketNumber(i), time.Time{}, true)
				}
				Expect(tracker.GetAckFrame()).ToNot(BeNil())
				Expect(tracker.ackQueued).To(BeFalse())
			}

			It("always queues an ACK for the first packet", func() {
				tracker.ReceivedPacket(1, time.Now(), false)
				Expect(tracker.ackQueued).To(BeTrue())
				Expect(tracker.GetAlarmTimeout()).To(BeZero())
				Expect(tracker.GetAckFrame().DelayTime).To(BeNumerically("~", 0, time.Second))
			})

			It("works with packet number 0", func() {
				tracker.ReceivedPacket(0, time.Now(), false)
				Expect(tracker.ackQueued).To(BeTrue())
				Expect(tracker.GetAlarmTimeout()).To(BeZero())
				Expect(tracker.GetAckFrame().DelayTime).To(BeNumerically("~", 0, time.Second))
			})

			It("queues an ACK for every second ack-eliciting packet at the beginning", func() {
				receiveAndAck10Packets()
				p := protocol.PacketNumber(11)
				for i := 0; i <= 20; i++ {
					tracker.ReceivedPacket(p, time.Time{}, true)
					Expect(tracker.ackQueued).To(BeFalse())
					p++
					tracker.ReceivedPacket(p, time.Time{}, true)
					Expect(tracker.ackQueued).To(BeTrue())
					p++
					// dequeue the ACK frame
					Expect(tracker.GetAckFrame()).ToNot(BeNil())
				}
			})

			It("queues an ACK for every 10 ack-eliciting packet, if they are arriving fast", func() {
				receiveAndAck10Packets()
				p := protocol.PacketNumber(10000)
				for i := 0; i < 9; i++ {
					tracker.ReceivedPacket(p, time.Now(), true)
					Expect(tracker.ackQueued).To(BeFalse())
					p++
				}
				Expect(tracker.GetAlarmTimeout()).NotTo(BeZero())
				tracker.ReceivedPacket(p, time.Now(), true)
				Expect(tracker.ackQueued).To(BeTrue())
				Expect(tracker.GetAlarmTimeout()).To(BeZero())
			})

			It("only sets the timer when receiving a ack-eliciting packets", func() {
				receiveAndAck10Packets()
				tracker.ReceivedPacket(11, time.Now(), false)
				Expect(tracker.ackQueued).To(BeFalse())
				Expect(tracker.GetAlarmTimeout()).To(BeZero())
				rcvTime := time.Now().Add(10 * time.Millisecond)
				tracker.ReceivedPacket(12, rcvTime, true)
				Expect(tracker.ackQueued).To(BeFalse())
				Expect(tracker.GetAlarmTimeout()).To(Equal(rcvTime.Add(protocol.MaxAckDelay)))
			})

			It("queues an ACK if it was reported missing before", func() {
				receiveAndAck10Packets()
				tracker.ReceivedPacket(11, time.Time{}, true)
				tracker.ReceivedPacket(13, time.Time{}, true)
				ack := tracker.GetAckFrame() // ACK: 1-11 and 13, missing: 12
				Expect(ack).ToNot(BeNil())
				Expect(ack.HasMissingRanges()).To(BeTrue())
				Expect(tracker.ackQueued).To(BeFalse())
				tracker.ReceivedPacket(12, time.Time{}, false)
				Expect(tracker.ackQueued).To(BeTrue())
			})

			It("doesn't queue an ACK if it was reported missing before, but is below the threshold", func() {
				receiveAndAck10Packets()
				// 11 is missing
				tracker.ReceivedPacket(12, time.Time{}, true)
				tracker.ReceivedPacket(13, time.Time{}, true)
				ack := tracker.GetAckFrame() // ACK: 1-10, 12-13
				Expect(ack).ToNot(BeNil())
				// now receive 11
				tracker.IgnoreBelow(12)
				tracker.ReceivedPacket(11, time.Time{}, false)
				ack = tracker.GetAckFrame()
				Expect(ack).To(BeNil())
			})

			It("doesn't queue an ACK if the packet closes a gap that was not yet reported", func() {
				receiveAndAckPacketsUntilAckDecimation()
				p := protocol.PacketNumber(minReceivedBeforeAckDecimation + 1)
				tracker.ReceivedPacket(p+1, time.Now(), true) // p is missing now
				Expect(tracker.ackQueued).To(BeFalse())
				Expect(tracker.GetAlarmTimeout()).ToNot(BeZero())
				tracker.ReceivedPacket(p, time.Now(), true) // p is not missing any more
				Expect(tracker.ackQueued).To(BeFalse())
			})

			It("sets an ACK alarm after 1/4 RTT if it creates a new missing range", func() {
				now := time.Now().Add(-time.Hour)
				rtt := 80 * time.Millisecond
				rttStats.UpdateRTT(rtt, 0, now)
				receiveAndAckPacketsUntilAckDecimation()
				p := protocol.PacketNumber(minReceivedBeforeAckDecimation + 1)
				for i := p; i < p+6; i++ {
					tracker.ReceivedPacket(i, now, true)
				}
				tracker.ReceivedPacket(p+10, now, true) // we now know that packets p+7, p+8 and p+9
				Expect(rttStats.MinRTT()).To(Equal(rtt))
				Expect(tracker.ackAlarm.Sub(now)).To(Equal(rtt / 8))
				ack := tracker.GetAckFrame()
				Expect(ack.HasMissingRanges()).To(BeTrue())
				Expect(ack).ToNot(BeNil())
			})
		})

		Context("ACK generation", func() {
			BeforeEach(func() {
				tracker.ackQueued = true
			})

			It("generates a simple ACK frame", func() {
				tracker.ReceivedPacket(1, time.Time{}, true)
				tracker.ReceivedPacket(2, time.Time{}, true)
				ack := tracker.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(2)))
				Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
				Expect(ack.HasMissingRanges()).To(BeFalse())
			})

			It("generates an ACK for packet number 0", func() {
				tracker.ReceivedPacket(0, time.Time{}, true)
				ack := tracker.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(0)))
				Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(0)))
				Expect(ack.HasMissingRanges()).To(BeFalse())
			})

			It("sets the delay time", func() {
				tracker.ReceivedPacket(1, time.Time{}, true)
				tracker.ReceivedPacket(2, time.Now().Add(-1337*time.Millisecond), true)
				ack := tracker.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.DelayTime).To(BeNumerically("~", 1337*time.Millisecond, 50*time.Millisecond))
			})

			It("uses a 0 delay time if the delay would be negative", func() {
				tracker.ReceivedPacket(0, time.Now().Add(time.Hour), true)
				ack := tracker.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.DelayTime).To(BeZero())
			})

			It("saves the last sent ACK", func() {
				tracker.ReceivedPacket(1, time.Time{}, true)
				ack := tracker.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(tracker.lastAck).To(Equal(ack))
				tracker.ReceivedPacket(2, time.Time{}, true)
				tracker.ackQueued = true
				ack = tracker.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(tracker.lastAck).To(Equal(ack))
			})

			It("generates an ACK frame with missing packets", func() {
				tracker.ReceivedPacket(1, time.Time{}, true)
				tracker.ReceivedPacket(4, time.Time{}, true)
				ack := tracker.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(4)))
				Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
				Expect(ack.AckRanges).To(Equal([]wire.AckRange{
					{Smallest: 4, Largest: 4},
					{Smallest: 1, Largest: 1},
				}))
			})

			It("generates an ACK for packet number 0 and other packets", func() {
				tracker.ReceivedPacket(0, time.Time{}, true)
				tracker.ReceivedPacket(1, time.Time{}, true)
				tracker.ReceivedPacket(3, time.Time{}, true)
				ack := tracker.GetAckFrame()
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
				tracker.ReceivedPacket(4, time.Time{}, true)
				tracker.ReceivedPacket(10, time.Time{}, true)
				ack := tracker.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(10)))
				Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(10)))
			})

			It("deletes packets from the packetHistory when a lower limit is set", func() {
				for i := 1; i <= 12; i++ {
					tracker.ReceivedPacket(protocol.PacketNumber(i), time.Time{}, true)
				}
				tracker.IgnoreBelow(7)
				// check that the packets were deleted from the receivedPacketHistory by checking the values in an ACK frame
				ack := tracker.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(12)))
				Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(7)))
				Expect(ack.HasMissingRanges()).To(BeFalse())
			})

			// TODO: remove this test when dropping support for STOP_WAITINGs
			It("handles a lower limit of 0", func() {
				tracker.IgnoreBelow(0)
				tracker.ReceivedPacket(1337, time.Time{}, true)
				ack := tracker.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(1337)))
			})

			It("resets all counters needed for the ACK queueing decision when sending an ACK", func() {
				tracker.ReceivedPacket(1, time.Time{}, true)
				tracker.ackAlarm = time.Now().Add(-time.Minute)
				Expect(tracker.GetAckFrame()).ToNot(BeNil())
				Expect(tracker.packetsReceivedSinceLastAck).To(BeZero())
				Expect(tracker.GetAlarmTimeout()).To(BeZero())
				Expect(tracker.ackElicitingPacketsReceivedSinceLastAck).To(BeZero())
				Expect(tracker.ackQueued).To(BeFalse())
			})

			It("doesn't generate an ACK when none is queued and the timer is not set", func() {
				tracker.ReceivedPacket(1, time.Time{}, true)
				tracker.ackQueued = false
				tracker.ackAlarm = time.Time{}
				Expect(tracker.GetAckFrame()).To(BeNil())
			})

			It("doesn't generate an ACK when none is queued and the timer has not yet expired", func() {
				tracker.ReceivedPacket(1, time.Time{}, true)
				tracker.ackQueued = false
				tracker.ackAlarm = time.Now().Add(time.Minute)
				Expect(tracker.GetAckFrame()).To(BeNil())
			})

			It("generates an ACK when the timer has expired", func() {
				tracker.ReceivedPacket(1, time.Time{}, true)
				tracker.ackQueued = false
				tracker.ackAlarm = time.Now().Add(-time.Minute)
				Expect(tracker.GetAckFrame()).ToNot(BeNil())
			})
		})
	})
})
