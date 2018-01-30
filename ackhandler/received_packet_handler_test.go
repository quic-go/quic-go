package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("receivedPacketHandler", func() {
	var (
		handler *receivedPacketHandler
	)

	BeforeEach(func() {
		handler = NewReceivedPacketHandler(protocol.VersionWhatever).(*receivedPacketHandler)
	})

	Context("accepting packets", func() {
		It("handles a packet that arrives late", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1), time.Time{}, true)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(3), time.Time{}, true)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(2), time.Time{}, true)
			Expect(err).ToNot(HaveOccurred())
		})

		It("saves the time when each packet arrived", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(3), time.Now(), true)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.largestObservedReceivedTime).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
		})

		It("updates the largestObserved and the largestObservedReceivedTime", func() {
			now := time.Now()
			handler.largestObserved = 3
			handler.largestObservedReceivedTime = now.Add(-1 * time.Second)
			err := handler.ReceivedPacket(5, now, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(5)))
			Expect(handler.largestObservedReceivedTime).To(Equal(now))
		})

		It("doesn't update the largestObserved and the largestObservedReceivedTime for a belated packet", func() {
			now := time.Now()
			timestamp := now.Add(-1 * time.Second)
			handler.largestObserved = 5
			handler.largestObservedReceivedTime = timestamp
			err := handler.ReceivedPacket(4, now, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(5)))
			Expect(handler.largestObservedReceivedTime).To(Equal(timestamp))
		})

		It("passes on errors from receivedPacketHistory", func() {
			var err error
			for i := protocol.PacketNumber(0); i < 5*protocol.MaxTrackedReceivedAckRanges; i++ {
				err = handler.ReceivedPacket(2*i+1, time.Time{}, true)
				// this will eventually return an error
				// details about when exactly the receivedPacketHistory errors are tested there
				if err != nil {
					break
				}
			}
			Expect(err).To(MatchError(errTooManyOutstandingReceivedAckRanges))
		})
	})

	Context("ACKs", func() {
		Context("queueing ACKs", func() {
			receiveAndAck10Packets := func() {
				for i := 1; i <= 10; i++ {
					err := handler.ReceivedPacket(protocol.PacketNumber(i), time.Time{}, true)
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(handler.GetAckFrame()).ToNot(BeNil())
				Expect(handler.ackQueued).To(BeFalse())
			}

			It("always queues an ACK for the first packet", func() {
				err := handler.ReceivedPacket(1, time.Time{}, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeTrue())
				Expect(handler.GetAlarmTimeout()).To(BeZero())
			})

			It("works with packet number 0", func() {
				err := handler.ReceivedPacket(0, time.Time{}, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeTrue())
				Expect(handler.GetAlarmTimeout()).To(BeZero())
			})

			It("queues an ACK for every RetransmittablePacketsBeforeAck retransmittable packet, if they are arriving fast", func() {
				receiveAndAck10Packets()
				p := protocol.PacketNumber(11)
				for i := 0; i < protocol.RetransmittablePacketsBeforeAck-1; i++ {
					err := handler.ReceivedPacket(p, time.Time{}, true)
					Expect(err).ToNot(HaveOccurred())
					Expect(handler.ackQueued).To(BeFalse())
					p++
				}
				Expect(handler.GetAlarmTimeout()).NotTo(BeZero())
				err := handler.ReceivedPacket(p, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeTrue())
				Expect(handler.GetAlarmTimeout()).To(BeZero())
			})

			It("only sets the timer when receiving a retransmittable packets", func() {
				receiveAndAck10Packets()
				err := handler.ReceivedPacket(11, time.Time{}, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeFalse())
				Expect(handler.ackAlarm).To(BeZero())
				err = handler.ReceivedPacket(12, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeFalse())
				Expect(handler.ackAlarm).ToNot(BeZero())
				Expect(handler.GetAlarmTimeout()).NotTo(BeZero())
			})

			It("queues an ACK if it was reported missing before", func() {
				receiveAndAck10Packets()
				err := handler.ReceivedPacket(11, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedPacket(13, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame() // ACK: 1 and 3, missing: 2
				Expect(ack).ToNot(BeNil())
				Expect(ack.HasMissingRanges()).To(BeTrue())
				Expect(handler.ackQueued).To(BeFalse())
				err = handler.ReceivedPacket(12, time.Time{}, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeTrue())
			})

			It("queues an ACK if it creates a new missing range", func() {
				receiveAndAck10Packets()
				for i := 11; i < 16; i++ {
					err := handler.ReceivedPacket(protocol.PacketNumber(i), time.Time{}, true)
					Expect(err).ToNot(HaveOccurred())
				}
				err := handler.ReceivedPacket(20, time.Time{}, true) // we now know that packets 16 to 19 are missing
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeTrue())
				ack := handler.GetAckFrame()
				Expect(ack.HasMissingRanges()).To(BeTrue())
				Expect(ack).ToNot(BeNil())
			})
		})

		Context("ACK generation", func() {
			BeforeEach(func() {
				handler.ackQueued = true
			})

			It("generates a simple ACK frame", func() {
				err := handler.ReceivedPacket(1, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedPacket(2, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(2)))
				Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(1)))
				Expect(ack.AckRanges).To(BeEmpty())
			})

			It("generates an ACK for packet number 0", func() {
				err := handler.ReceivedPacket(0, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(0)))
				Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(0)))
				Expect(ack.AckRanges).To(BeEmpty())
			})

			It("saves the last sent ACK", func() {
				err := handler.ReceivedPacket(1, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(handler.lastAck).To(Equal(ack))
				err = handler.ReceivedPacket(2, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				handler.ackQueued = true
				ack = handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(handler.lastAck).To(Equal(ack))
			})

			It("generates an ACK frame with missing packets", func() {
				err := handler.ReceivedPacket(1, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedPacket(4, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(4)))
				Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(1)))
				Expect(ack.AckRanges).To(Equal([]wire.AckRange{
					wire.AckRange{First: 4, Last: 4},
					wire.AckRange{First: 1, Last: 1},
				}))
			})

			It("generates an ACK for packet number 0 and other packets", func() {
				err := handler.ReceivedPacket(0, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedPacket(1, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedPacket(3, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(0)))
				Expect(ack.AckRanges).To(Equal([]wire.AckRange{
					wire.AckRange{First: 3, Last: 3},
					wire.AckRange{First: 0, Last: 1},
				}))
			})

			It("accepts packets below the lower limit", func() {
				handler.IgnoreBelow(6)
				err := handler.ReceivedPacket(2, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
			})

			It("doesn't add delayed packets to the packetHistory", func() {
				handler.IgnoreBelow(7)
				err := handler.ReceivedPacket(4, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedPacket(10, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(10)))
				Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(10)))
			})

			It("deletes packets from the packetHistory when a lower limit is set", func() {
				for i := 1; i <= 12; i++ {
					err := handler.ReceivedPacket(protocol.PacketNumber(i), time.Time{}, true)
					Expect(err).ToNot(HaveOccurred())
				}
				handler.IgnoreBelow(7)
				// check that the packets were deleted from the receivedPacketHistory by checking the values in an ACK frame
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(12)))
				Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(7)))
				Expect(ack.HasMissingRanges()).To(BeFalse())
			})

			// TODO: remove this test when dropping support for STOP_WAITINGs
			It("handles a lower limit of 0", func() {
				handler.IgnoreBelow(0)
				err := handler.ReceivedPacket(1337, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(1337)))
			})

			It("resets all counters needed for the ACK queueing decision when sending an ACK", func() {
				err := handler.ReceivedPacket(1, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				handler.ackAlarm = time.Now().Add(-time.Minute)
				Expect(handler.GetAckFrame()).ToNot(BeNil())
				Expect(handler.packetsReceivedSinceLastAck).To(BeZero())
				Expect(handler.ackAlarm).To(BeZero())
				Expect(handler.retransmittablePacketsReceivedSinceLastAck).To(BeZero())
				Expect(handler.ackQueued).To(BeFalse())
			})

			It("doesn't generate an ACK when none is queued and the timer is not set", func() {
				err := handler.ReceivedPacket(1, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				handler.ackQueued = false
				handler.ackAlarm = time.Time{}
				Expect(handler.GetAckFrame()).To(BeNil())
			})

			It("doesn't generate an ACK when none is queued and the timer has not yet expired", func() {
				err := handler.ReceivedPacket(1, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				handler.ackQueued = false
				handler.ackAlarm = time.Now().Add(time.Minute)
				Expect(handler.GetAckFrame()).To(BeNil())
			})

			It("generates an ACK when the timer has expired", func() {
				err := handler.ReceivedPacket(1, time.Time{}, true)
				Expect(err).ToNot(HaveOccurred())
				handler.ackQueued = false
				handler.ackAlarm = time.Now().Add(-time.Minute)
				Expect(handler.GetAckFrame()).ToNot(BeNil())
			})
		})
	})
})
