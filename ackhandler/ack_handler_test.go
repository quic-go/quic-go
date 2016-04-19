package ackhandler

import (
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AckHandler", func() {
	It("Returns no NACK ranges for continously received packets", func() {
		ackHandler, _ := NewAckHandler()
		for i := 0; i < 100; i++ {
			ackHandler.HandlePacket(protocol.PacketNumber(i))
		}
		Expect(ackHandler.LargestObserved).To(Equal(protocol.PacketNumber(99)))
		Expect(len(ackHandler.GetNackRanges())).To(Equal(0))
	})

	It("handles a single lost package", func() {
		ackHandler, _ := NewAckHandler()
		for i := 0; i < 10; i++ {
			if i == 5 {
				continue
			}
			ackHandler.HandlePacket(protocol.PacketNumber(i))
		}
		Expect(ackHandler.LargestObserved).To(Equal(protocol.PacketNumber(9)))
		nackRanges := ackHandler.GetNackRanges()
		Expect(len(nackRanges)).To(Equal(1))
		Expect(nackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(5)))
		Expect(nackRanges[0].Length).To(Equal(uint8(1)))
	})

	It("handles two consecutive lost packages", func() {
		ackHandler, _ := NewAckHandler()
		for i := 0; i < 10; i++ {
			if i == 5 || i == 6 {
				continue
			}
			ackHandler.HandlePacket(protocol.PacketNumber(i))
		}
		Expect(ackHandler.LargestObserved).To(Equal(protocol.PacketNumber(9)))
		nackRanges := ackHandler.GetNackRanges()
		Expect(len(nackRanges)).To(Equal(1))
		Expect(nackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(5)))
		Expect(nackRanges[0].Length).To(Equal(uint8(2)))
	})

	It("handles two non-consecutively lost packages", func() {
		ackHandler, _ := NewAckHandler()
		for i := 0; i < 10; i++ {
			if i == 3 || i == 7 {
				continue
			}
			ackHandler.HandlePacket(protocol.PacketNumber(i))
		}
		Expect(ackHandler.LargestObserved).To(Equal(protocol.PacketNumber(9)))
		nackRanges := ackHandler.GetNackRanges()
		Expect(len(nackRanges)).To(Equal(2))
		Expect(nackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(3)))
		Expect(nackRanges[0].Length).To(Equal(uint8(1)))
		Expect(nackRanges[1].FirstPacketNumber).To(Equal(protocol.PacketNumber(7)))
		Expect(nackRanges[1].Length).To(Equal(uint8(1)))
	})

	It("handles two sequences of lost packages", func() {
		ackHandler, _ := NewAckHandler()
		for i := 0; i < 10; i++ {
			if i == 2 || i == 3 || i == 4 || i == 7 || i == 8 {
				continue
			}
			ackHandler.HandlePacket(protocol.PacketNumber(i))
		}
		Expect(ackHandler.LargestObserved).To(Equal(protocol.PacketNumber(9)))
		nackRanges := ackHandler.GetNackRanges()
		Expect(len(nackRanges)).To(Equal(2))
		Expect(nackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(2)))
		Expect(nackRanges[0].Length).To(Equal(uint8(3)))
		Expect(nackRanges[1].FirstPacketNumber).To(Equal(protocol.PacketNumber(7)))
		Expect(nackRanges[1].Length).To(Equal(uint8(2)))
	})

})
