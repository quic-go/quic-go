package ackhandlernew

import (
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("StopWaitingManager", func() {
	var manager *stopWaitingManager
	BeforeEach(func() {
		manager = NewStopWaitingManager().(*stopWaitingManager)
	})

	It("returns nil in the beginning", func() {
		Expect(manager.GetStopWaitingFrame()).To(BeNil())
	})

	It("gets a StopWaitingFrame after a packet has been registered for retransmission", func() {
		leastUnacked := protocol.PacketNumber(10)
		manager.RegisterPacketForRetransmission(&Packet{PacketNumber: leastUnacked})
		swf := manager.GetStopWaitingFrame()
		Expect(swf).ToNot(BeNil())
		Expect(swf.LeastUnacked).To(Equal(leastUnacked + 1))
	})

	It("always gets the StopWaitingFrame for the highest retransmitted packet number", func() {
		leastUnacked := protocol.PacketNumber(10)
		manager.RegisterPacketForRetransmission(&Packet{PacketNumber: leastUnacked})
		manager.RegisterPacketForRetransmission(&Packet{PacketNumber: leastUnacked - 1})
		swf := manager.GetStopWaitingFrame()
		Expect(swf).ToNot(BeNil())
		Expect(swf.LeastUnacked).To(Equal(leastUnacked + 1))
	})

	It("updates the StopWaitingFrame when a packet with a higher packet number is retransmitted", func() {
		leastUnacked := protocol.PacketNumber(10)
		manager.RegisterPacketForRetransmission(&Packet{PacketNumber: leastUnacked - 1})
		manager.RegisterPacketForRetransmission(&Packet{PacketNumber: leastUnacked})
		swf := manager.GetStopWaitingFrame()
		Expect(swf).ToNot(BeNil())
		Expect(swf.LeastUnacked).To(Equal(leastUnacked + 1))
	})

	It("does not create a new StopWaitingFrame for an out-of-order retransmission", func() {
		leastUnacked := protocol.PacketNumber(10)
		manager.RegisterPacketForRetransmission(&Packet{PacketNumber: leastUnacked})
		manager.SentStopWaitingWithPacket(12)
		manager.ReceivedAckForPacketNumber(12)
		manager.RegisterPacketForRetransmission(&Packet{PacketNumber: leastUnacked - 1})
		swf := manager.GetStopWaitingFrame()
		Expect(swf).To(BeNil())
	})

	Context("ACK handling", func() {
		It("removes the current StopWaitingFrame when the first packet it was sent with is ACKed", func() {
			manager.RegisterPacketForRetransmission(&Packet{PacketNumber: 10})
			manager.SentStopWaitingWithPacket(13)
			manager.SentStopWaitingWithPacket(14)
			manager.SentStopWaitingWithPacket(15)
			Expect(manager.GetStopWaitingFrame()).ToNot(BeNil())
			manager.ReceivedAckForPacketNumber(13)
			Expect(manager.GetStopWaitingFrame()).To(BeNil())
		})

		It("removes the current StopWaitingFrame when any packet it was sent with is ACKed", func() {
			manager.RegisterPacketForRetransmission(&Packet{PacketNumber: 10})
			manager.SentStopWaitingWithPacket(13)
			manager.SentStopWaitingWithPacket(14)
			manager.SentStopWaitingWithPacket(15)
			Expect(manager.GetStopWaitingFrame()).ToNot(BeNil())
			manager.ReceivedAckForPacketNumber(14)
			Expect(manager.GetStopWaitingFrame()).To(BeNil())
		})

		It("does not remove the current StopWaitingFrame when a packet before the one containing the StopWaitingFrame is ACKed", func() {
			manager.RegisterPacketForRetransmission(&Packet{PacketNumber: 10})
			manager.SentStopWaitingWithPacket(13)
			Expect(manager.GetStopWaitingFrame()).ToNot(BeNil())
			manager.ReceivedAckForPacketNumber(12)
			Expect(manager.GetStopWaitingFrame()).ToNot(BeNil())
		})
	})
})
