package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("receivedPacketHandler", func() {
	var (
		handler *receivedPacketHandler
	)

	BeforeEach(func() {
		handler = NewReceivedPacketHandler().(*receivedPacketHandler)
	})

	Context("accepting packets", func() {
		It("handles a packet that arrives late", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(1)))
			err = handler.ReceivedPacket(protocol.PacketNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(3)))
			err = handler.ReceivedPacket(protocol.PacketNumber(2))
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(2)))
		})

		It("rejects packets with packet number 0", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(0))
			Expect(err).To(MatchError(errInvalidPacketNumber))
		})

		It("rejects a duplicate package with PacketNumber equal to LargestObserved", func() {
			for i := 1; i < 5; i++ {
				err := handler.ReceivedPacket(protocol.PacketNumber(i))
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedPacket(4)
			Expect(err).To(MatchError(ErrDuplicatePacket))
		})

		It("rejects a duplicate package with PacketNumber less than the LargestObserved", func() {
			for i := 1; i < 5; i++ {
				err := handler.ReceivedPacket(protocol.PacketNumber(i))
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedPacket(2)
			Expect(err).To(MatchError(ErrDuplicatePacket))
		})

		It("ignores a packet with PacketNumber less than the LeastUnacked of a previously received StopWaiting", func() {
			err := handler.ReceivedPacket(5)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: 10})
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(9)
			Expect(err).To(MatchError(ErrPacketSmallerThanLastStopWaiting))
			Expect(handler.largestInOrderObserved).To(Equal(protocol.PacketNumber(9)))
		})

		It("does not ignore a packet with PacketNumber equal to LeastUnacked of a previously received StopWaiting", func() {
			err := handler.ReceivedPacket(5)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: 10})
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(10)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.largestInOrderObserved).To(Equal(protocol.PacketNumber(10)))
		})

		It("saves the time when each packet arrived", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(3)))
			Expect(handler.receivedTimes[3]).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
		})

		It("doesn't store more than MaxTrackedReceivedPackets packets", func() {
			for i := protocol.PacketNumber(0); i < protocol.MaxTrackedReceivedPackets; i++ {
				packetNumber := protocol.PacketNumber(1 + 2*i)
				err := handler.ReceivedPacket(packetNumber)
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedPacket(protocol.PacketNumber(3 * protocol.MaxTrackedReceivedPackets))
			Expect(err).To(MatchError(errTooManyOutstandingReceivedPackets))
		})
	})

	Context("handling STOP_WAITING frames", func() {
		It("increases the largestInOrderObserved packet number", func() {
			// We simulate 20 packets, numbers 10, 11 and 12 lost
			for i := 1; i < 20; i++ {
				if i == 10 || i == 11 || i == 12 {
					continue
				}
				err := handler.ReceivedPacket(protocol.PacketNumber(i))
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: protocol.PacketNumber(12)})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.largestInOrderObserved).To(Equal(protocol.PacketNumber(11)))
		})

		It("increases the ignorePacketsBelow number", func() {
			err := handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: protocol.PacketNumber(12)})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.ignorePacketsBelow).To(Equal(protocol.PacketNumber(11)))
		})

		It("increase the ignorePacketsBelow number, even if all packets below the LeastUnacked were already acked", func() {
			for i := 1; i < 20; i++ {
				err := handler.ReceivedPacket(protocol.PacketNumber(i))
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.largestInOrderObserved).To(Equal(protocol.PacketNumber(19)))
			err := handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: protocol.PacketNumber(12)})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.ignorePacketsBelow).To(Equal(protocol.PacketNumber(11)))
		})

		It("does not decrease the ignorePacketsBelow number when an out-of-order StopWaiting arrives", func() {
			err := handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: protocol.PacketNumber(12)})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.ignorePacketsBelow).To(Equal(protocol.PacketNumber(11)))
			err = handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: protocol.PacketNumber(6)})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.ignorePacketsBelow).To(Equal(protocol.PacketNumber(11)))
		})
	})

	Context("ACK package generation", func() {
		It("generates a simple ACK frame", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1))
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(2))
			Expect(err).ToNot(HaveOccurred())
			ack, err := handler.GetAckFrame(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(2)))
			Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(1)))
			Expect(ack.AckRanges).To(BeEmpty())
		})

		It("generates an ACK frame with missing packets", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1))
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(4))
			Expect(err).ToNot(HaveOccurred())
			ack, err := handler.GetAckFrame(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(4)))
			Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(1)))
			Expect(ack.AckRanges).To(HaveLen(2))
			Expect(ack.AckRanges[0]).To(Equal(frames.AckRange{FirstPacketNumber: 4, LastPacketNumber: 4}))
			Expect(ack.AckRanges[1]).To(Equal(frames.AckRange{FirstPacketNumber: 1, LastPacketNumber: 1}))
		})

		It("does not generate an ACK if an ACK has already been sent for the largest Packet", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1))
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(2))
			Expect(err).ToNot(HaveOccurred())
			ack, err := handler.GetAckFrame(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).ToNot(BeNil())
			ack, err = handler.GetAckFrame(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).To(BeNil())
		})

		It("does not dequeue an ACK frame if told so", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(2))
			Expect(err).ToNot(HaveOccurred())
			ack, err := handler.GetAckFrame(false)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).ToNot(BeNil())
			ack, err = handler.GetAckFrame(false)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).ToNot(BeNil())
			ack, err = handler.GetAckFrame(false)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).ToNot(BeNil())
		})

		It("returns a cached ACK frame if the ACK was not dequeued", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(2))
			Expect(err).ToNot(HaveOccurred())
			ack, err := handler.GetAckFrame(false)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).ToNot(BeNil())
			ack2, err := handler.GetAckFrame(false)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack2).ToNot(BeNil())
			Expect(&ack).To(Equal(&ack2))
		})

		It("generates a new ACK (and deletes the cached one) when a new packet arrives", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1))
			Expect(err).ToNot(HaveOccurred())
			ack, _ := handler.GetAckFrame(true)
			Expect(ack).ToNot(BeNil())
			Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(1)))
			err = handler.ReceivedPacket(protocol.PacketNumber(3))
			Expect(err).ToNot(HaveOccurred())
			ack, _ = handler.GetAckFrame(true)
			Expect(ack).ToNot(BeNil())
			Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(3)))
		})

		It("generates a new ACK when an out-of-order packet arrives", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1))
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(3))
			Expect(err).ToNot(HaveOccurred())
			ack, _ := handler.GetAckFrame(true)
			Expect(ack).ToNot(BeNil())
			Expect(ack.AckRanges).To(HaveLen(2))
			err = handler.ReceivedPacket(protocol.PacketNumber(2))
			Expect(err).ToNot(HaveOccurred())
			ack, _ = handler.GetAckFrame(true)
			Expect(ack).ToNot(BeNil())
			Expect(ack.AckRanges).To(BeEmpty())
		})

		It("doesn't send old ACK ranges after receiving a StopWaiting", func() {
			err := handler.ReceivedPacket(5)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(10)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(11)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(12)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: protocol.PacketNumber(11)})
			Expect(err).ToNot(HaveOccurred())
			ack, err := handler.GetAckFrame(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).ToNot(BeNil())
			Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(12)))
			Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(11)))
			Expect(ack.HasMissingRanges()).To(BeFalse())
		})

		It("deletes packets from the packetHistory after receiving a StopWaiting, after continuously received packets", func() {
			for i := 1; i <= 12; i++ {
				err := handler.ReceivedPacket(protocol.PacketNumber(i))
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: protocol.PacketNumber(6)})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.largestInOrderObserved).To(Equal(protocol.PacketNumber(12)))
			// check that the packets were deleted from the receivedPacketHistory by checking the values in an ACK frame
			ack, err := handler.GetAckFrame(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).ToNot(BeNil())
			Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(12)))
			Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(6)))
			Expect(ack.HasMissingRanges()).To(BeFalse())
		})
	})

	Context("Garbage Collector", func() {
		It("garbage collects receivedTimes after receiving a StopWaiting, if there are no missing packets", func() {
			for i := 1; i <= 4; i++ {
				err := handler.ReceivedPacket(protocol.PacketNumber(i))
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: 3})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.receivedTimes).ToNot(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.receivedTimes).ToNot(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(3)))
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(4)))
			Expect(handler.lowestInReceivedTimes).To(Equal(protocol.PacketNumber(3)))
		})

		It("garbage collects the receivedTimes after receiving multiple StopWaitings", func() {
			for i := 1; i <= 9; i++ {
				err := handler.ReceivedPacket(protocol.PacketNumber(i))
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: 4})
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: 8})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.receivedTimes).To(HaveLen(2)) // packets 8 and 9
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(8)))
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(9)))
			Expect(handler.lowestInReceivedTimes).To(Equal(protocol.PacketNumber(8)))
		})

		It("garbage collects receivedTimes after receiving a StopWaiting, if there are missing packets", func() {
			err := handler.ReceivedPacket(1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(2)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(4)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: 4})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.receivedTimes).ToNot(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.receivedTimes).ToNot(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(4)))
			Expect(handler.lowestInReceivedTimes).To(Equal(protocol.PacketNumber(4)))
		})
	})
})
