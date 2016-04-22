package ackhandler

import (
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("incomingPacketAckHandler", func() {
	var handler *incomingPacketAckHandler

	BeforeEach(func() {
		handler = NewIncomingPacketAckHandler().(*incomingPacketAckHandler)
	})

	It("Returns no NACK ranges for continously received packets", func() {
		for i := 1; i < 100; i++ {
			err := handler.ReceivedPacket(protocol.PacketNumber(i), false)
			Expect(err).ToNot(HaveOccurred())
		}
		Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(99)))
		Expect(len(handler.getNackRanges())).To(Equal(0))
	})

	It("handles a single lost package", func() {
		for i := 1; i < 10; i++ {
			if i == 5 {
				continue
			}
			handler.ReceivedPacket(protocol.PacketNumber(i), false)
		}
		Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(9)))
		nackRanges := handler.getNackRanges()
		Expect(len(nackRanges)).To(Equal(1))
		Expect(nackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(5)))
		Expect(nackRanges[0].LastPacketNumber).To(Equal(protocol.PacketNumber(5)))
	})

	It("handles two consecutive lost packages", func() {
		for i := 1; i < 10; i++ {
			if i == 5 || i == 6 {
				continue
			}
			handler.ReceivedPacket(protocol.PacketNumber(i), false)
		}
		Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(9)))
		nackRanges := handler.getNackRanges()
		Expect(len(nackRanges)).To(Equal(1))
		Expect(nackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(5)))
		Expect(nackRanges[0].LastPacketNumber).To(Equal(protocol.PacketNumber(6)))
	})

	It("handles two non-consecutively lost packages", func() {
		for i := 1; i < 10; i++ {
			if i == 3 || i == 7 {
				continue
			}
			handler.ReceivedPacket(protocol.PacketNumber(i), false)
		}
		Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(9)))
		nackRanges := handler.getNackRanges()
		Expect(len(nackRanges)).To(Equal(2))
		Expect(nackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(3)))
		Expect(nackRanges[0].LastPacketNumber).To(Equal(protocol.PacketNumber(3)))
		Expect(nackRanges[1].FirstPacketNumber).To(Equal(protocol.PacketNumber(7)))
		Expect(nackRanges[1].LastPacketNumber).To(Equal(protocol.PacketNumber(7)))
	})

	It("handles two sequences of lost packages", func() {
		for i := 1; i < 10; i++ {
			if i == 2 || i == 3 || i == 4 || i == 7 || i == 8 {
				continue
			}
			handler.ReceivedPacket(protocol.PacketNumber(i), false)
		}
		Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(9)))
		nackRanges := handler.getNackRanges()
		Expect(len(nackRanges)).To(Equal(2))
		Expect(nackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(2)))
		Expect(nackRanges[0].LastPacketNumber).To(Equal(protocol.PacketNumber(4)))
		Expect(nackRanges[1].FirstPacketNumber).To(Equal(protocol.PacketNumber(7)))
		Expect(nackRanges[1].LastPacketNumber).To(Equal(protocol.PacketNumber(8)))
	})

	It("handles a packet that arrives late", func() {
		err := handler.ReceivedPacket(protocol.PacketNumber(1), false)
		Expect(err).ToNot(HaveOccurred())
		err = handler.ReceivedPacket(protocol.PacketNumber(3), false)
		Expect(err).ToNot(HaveOccurred())
		err = handler.ReceivedPacket(protocol.PacketNumber(2), false)
		Expect(err).ToNot(HaveOccurred())
		nackRanges := handler.getNackRanges()
		Expect(len(nackRanges)).To(Equal(0))
	})

	It("rejects a duplicate package with PacketNumber equal to LargestObserved", func() {
		for i := 1; i < 5; i++ {
			err := handler.ReceivedPacket(protocol.PacketNumber(i), false)
			Expect(err).ToNot(HaveOccurred())
		}
		err := handler.ReceivedPacket(4, false)
		Expect(err).To(HaveOccurred())
		Expect(err).To(Equal(ErrDuplicatePacket))
	})

	It("rejects a duplicate package with PacketNumber less than the LargestObserved", func() {
		for i := 1; i < 5; i++ {
			err := handler.ReceivedPacket(protocol.PacketNumber(i), false)
			Expect(err).ToNot(HaveOccurred())
		}
		err := handler.ReceivedPacket(2, false)
		Expect(err).To(HaveOccurred())
		Expect(err).To(Equal(ErrDuplicatePacket))
	})

})
