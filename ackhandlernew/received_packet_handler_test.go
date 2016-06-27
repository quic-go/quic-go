package ackhandlernew

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

		It("saves the time when each packet arrived", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(3)))
			Expect(handler.receivedTimes[3]).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
		})

		It("doesn't store more than MaxTrackedReceivedPackets packets", func() {
			for i := uint32(0); i < protocol.MaxTrackedReceivedPackets; i++ {
				packetNumber := protocol.PacketNumber(1 + 2*i)
				err := handler.ReceivedPacket(packetNumber)
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedPacket(protocol.PacketNumber(3 * protocol.MaxTrackedReceivedPackets))
			Expect(err).To(MatchError(errTooManyOutstandingReceivedPackets))
		})
	})

	Context("ACK range calculation", func() {
		It("Returns one ACK range for continously received packets", func() {
			for i := 1; i < 100; i++ {
				err := handler.ReceivedPacket(protocol.PacketNumber(i))
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(99)))
			// Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(99)))
			ackRanges := handler.getAckRanges()
			Expect(ackRanges).To(HaveLen(1))
			Expect(ackRanges[0]).To(Equal(frames.AckRange{FirstPacketNumber: 1, LastPacketNumber: 99}))
		})

		It("handles a single lost package", func() {
			for i := 1; i < 10; i++ {
				if i == 5 {
					continue
				}
				err := handler.ReceivedPacket(protocol.PacketNumber(i))
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(9)))
			ackRanges := handler.getAckRanges()
			Expect(ackRanges).To(HaveLen(2))
			Expect(ackRanges[0]).To(Equal(frames.AckRange{FirstPacketNumber: 6, LastPacketNumber: 9}))
			Expect(ackRanges[1]).To(Equal(frames.AckRange{FirstPacketNumber: 1, LastPacketNumber: 4}))
			// Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(4)))
		})

		It("handles two consecutive lost packages", func() {
			for i := 1; i < 12; i++ {
				if i == 5 || i == 6 {
					continue
				}
				err := handler.ReceivedPacket(protocol.PacketNumber(i))
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(11)))
			ackRanges := handler.getAckRanges()
			Expect(ackRanges).To(HaveLen(2))
			Expect(ackRanges[0]).To(Equal(frames.AckRange{FirstPacketNumber: 7, LastPacketNumber: 11}))
			Expect(ackRanges[1]).To(Equal(frames.AckRange{FirstPacketNumber: 1, LastPacketNumber: 4}))
			// Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(4)))
		})

		It("handles two non-consecutively lost packages", func() {
			for i := 1; i < 10; i++ {
				if i == 3 || i == 7 {
					continue
				}
				err := handler.ReceivedPacket(protocol.PacketNumber(i))
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(9)))
			ackRanges := handler.getAckRanges()
			Expect(ackRanges).To(HaveLen(3))
			Expect(ackRanges[0]).To(Equal(frames.AckRange{FirstPacketNumber: 8, LastPacketNumber: 9}))
			Expect(ackRanges[1]).To(Equal(frames.AckRange{FirstPacketNumber: 4, LastPacketNumber: 6}))
			Expect(ackRanges[2]).To(Equal(frames.AckRange{FirstPacketNumber: 1, LastPacketNumber: 2}))
			// Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(2)))
		})

		It("handles two sequences of lost packages", func() {
			for i := 1; i < 15; i++ {
				if i == 2 || i == 3 || i == 4 || i == 7 || i == 8 {
					continue
				}
				err := handler.ReceivedPacket(protocol.PacketNumber(i))
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(14)))
			ackRanges := handler.getAckRanges()
			Expect(ackRanges).To(HaveLen(3))
			Expect(ackRanges[0]).To(Equal(frames.AckRange{FirstPacketNumber: 9, LastPacketNumber: 14}))
			Expect(ackRanges[1]).To(Equal(frames.AckRange{FirstPacketNumber: 5, LastPacketNumber: 6}))
			Expect(ackRanges[2]).To(Equal(frames.AckRange{FirstPacketNumber: 1, LastPacketNumber: 1}))
			// Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(1)))
		})
	})

	Context("handling STOP_WAITING frames", func() {
		It("increases the highestInOrderObserved packet number", func() {
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
			Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(11)))
		})

		It("does not emit ACK ranges after STOP_WAITING", func() {
			err := handler.ReceivedPacket(10)
			Expect(err).ToNot(HaveOccurred())
			ranges := handler.getAckRanges()
			Expect(ranges).To(HaveLen(1))
			err = handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: protocol.PacketNumber(10)})
			Expect(err).ToNot(HaveOccurred())
			ranges = handler.getAckRanges()
			Expect(ranges).To(HaveLen(1))
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
	})

	Context("Garbage Collector", func() {
		PIt("only keeps packets with packet numbers higher than the highestInOrderObserved in packetHistory", func() {
			handler.ReceivedPacket(1)
			handler.ReceivedPacket(2)
			handler.ReceivedPacket(4)
			Expect(handler.receivedTimes).ToNot(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(4)))
		})

		It("garbage collects packetHistory after receiving a StopWaiting", func() {
			handler.ReceivedPacket(1)
			handler.ReceivedPacket(2)
			handler.ReceivedPacket(4)
			swf := frames.StopWaitingFrame{LeastUnacked: 4}
			handler.ReceivedStopWaiting(&swf)
			Expect(handler.receivedTimes).ToNot(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.receivedTimes).ToNot(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.receivedTimes).To(HaveKey(protocol.PacketNumber(4)))
		})
	})
})
