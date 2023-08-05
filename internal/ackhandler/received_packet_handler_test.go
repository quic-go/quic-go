package ackhandler

import (
	"time"

	"github.com/golang/mock/gomock"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Received Packet Handler", func() {
	var handler ReceivedPacketHandler
	var sentPackets *MockSentPacketTracker

	BeforeEach(func() {
		sentPackets = NewMockSentPacketTracker(mockCtrl)
		handler = newReceivedPacketHandler(
			sentPackets,
			&utils.RTTStats{},
			utils.DefaultLogger,
		)
	})

	It("generates ACKs for different packet number spaces", func() {
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
		sendTime := time.Now().Add(-time.Second)
		sentPackets.EXPECT().ReceivedPacket(protocol.EncryptionInitial).Times(2)
		sentPackets.EXPECT().ReceivedPacket(protocol.EncryptionHandshake).Times(2)
		sentPackets.EXPECT().ReceivedPacket(protocol.Encryption1RTT).Times(2)
		Expect(handler.ReceivedPacket(2, protocol.ECT0, protocol.EncryptionInitial, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(1, protocol.ECT1, protocol.EncryptionHandshake, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(5, protocol.ECNCE, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(3, protocol.ECT0, protocol.EncryptionInitial, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(2, protocol.ECT1, protocol.EncryptionHandshake, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(4, protocol.ECNCE, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		initialAck := handler.GetAckFrame(protocol.EncryptionInitial, true)
		Expect(initialAck).ToNot(BeNil())
		Expect(initialAck.AckRanges).To(HaveLen(1))
		Expect(initialAck.AckRanges[0]).To(Equal(wire.AckRange{Smallest: 2, Largest: 3}))
		Expect(initialAck.DelayTime).To(BeZero())
		Expect(initialAck.ECT0).To(BeEquivalentTo(2))
		Expect(initialAck.ECT1).To(BeZero())
		Expect(initialAck.ECNCE).To(BeZero())
		handshakeAck := handler.GetAckFrame(protocol.EncryptionHandshake, true)
		Expect(handshakeAck).ToNot(BeNil())
		Expect(handshakeAck.AckRanges).To(HaveLen(1))
		Expect(handshakeAck.AckRanges[0]).To(Equal(wire.AckRange{Smallest: 1, Largest: 2}))
		Expect(handshakeAck.DelayTime).To(BeZero())
		Expect(handshakeAck.ECT0).To(BeZero())
		Expect(handshakeAck.ECT1).To(BeEquivalentTo(2))
		Expect(handshakeAck.ECNCE).To(BeZero())
		oneRTTAck := handler.GetAckFrame(protocol.Encryption1RTT, true)
		Expect(oneRTTAck).ToNot(BeNil())
		Expect(oneRTTAck.AckRanges).To(HaveLen(1))
		Expect(oneRTTAck.AckRanges[0]).To(Equal(wire.AckRange{Smallest: 4, Largest: 5}))
		Expect(oneRTTAck.DelayTime).To(BeNumerically("~", time.Second, 50*time.Millisecond))
		Expect(oneRTTAck.ECT0).To(BeZero())
		Expect(oneRTTAck.ECT1).To(BeZero())
		Expect(oneRTTAck.ECNCE).To(BeEquivalentTo(2))
	})

	It("uses the same packet number space for 0-RTT and 1-RTT packets", func() {
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
		sentPackets.EXPECT().ReceivedPacket(protocol.Encryption0RTT)
		sentPackets.EXPECT().ReceivedPacket(protocol.Encryption1RTT)
		sendTime := time.Now().Add(-time.Second)
		Expect(handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		ack := handler.GetAckFrame(protocol.Encryption1RTT, true)
		Expect(ack).ToNot(BeNil())
		Expect(ack.AckRanges).To(HaveLen(1))
		Expect(ack.AckRanges[0]).To(Equal(wire.AckRange{Smallest: 2, Largest: 3}))
	})

	It("rejects 0-RTT packets with higher packet numbers than 1-RTT packets", func() {
		sentPackets.EXPECT().ReceivedPacket(gomock.Any()).Times(3)
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
		sendTime := time.Now()
		Expect(handler.ReceivedPacket(10, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(11, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(12, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true)).To(MatchError("received packet number 12 on a 0-RTT packet after receiving 11 on a 1-RTT packet"))
	})

	It("allows reordered 0-RTT packets", func() {
		sentPackets.EXPECT().ReceivedPacket(gomock.Any()).Times(3)
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
		sendTime := time.Now()
		Expect(handler.ReceivedPacket(10, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(12, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(11, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true)).To(Succeed())
	})

	It("drops Initial packets", func() {
		sentPackets.EXPECT().ReceivedPacket(gomock.Any()).Times(2)
		sendTime := time.Now().Add(-time.Second)
		Expect(handler.ReceivedPacket(2, protocol.ECNNon, protocol.EncryptionInitial, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(1, protocol.ECNNon, protocol.EncryptionHandshake, sendTime, true)).To(Succeed())
		Expect(handler.GetAckFrame(protocol.EncryptionInitial, true)).ToNot(BeNil())
		handler.DropPackets(protocol.EncryptionInitial)
		Expect(handler.GetAckFrame(protocol.EncryptionInitial, true)).To(BeNil())
		Expect(handler.GetAckFrame(protocol.EncryptionHandshake, true)).ToNot(BeNil())
	})

	It("drops Handshake packets", func() {
		sentPackets.EXPECT().ReceivedPacket(gomock.Any()).Times(2)
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
		sendTime := time.Now().Add(-time.Second)
		Expect(handler.ReceivedPacket(1, protocol.ECNNon, protocol.EncryptionHandshake, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		Expect(handler.GetAckFrame(protocol.EncryptionHandshake, true)).ToNot(BeNil())
		handler.DropPackets(protocol.EncryptionInitial)
		Expect(handler.GetAckFrame(protocol.EncryptionHandshake, true)).To(BeNil())
		Expect(handler.GetAckFrame(protocol.Encryption1RTT, true)).ToNot(BeNil())
	})

	It("does nothing when dropping 0-RTT packets", func() {
		handler.DropPackets(protocol.Encryption0RTT)
	})

	It("drops old ACK ranges", func() {
		sentPackets.EXPECT().ReceivedPacket(gomock.Any()).AnyTimes()
		sendTime := time.Now()
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().Times(2)
		Expect(handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		ack := handler.GetAckFrame(protocol.Encryption1RTT, true)
		Expect(ack).ToNot(BeNil())
		Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
		Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(2)))
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked()
		Expect(handler.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().Return(protocol.PacketNumber(2))
		Expect(handler.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		ack = handler.GetAckFrame(protocol.Encryption1RTT, true)
		Expect(ack).ToNot(BeNil())
		Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(2)))
		Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(4)))
	})

	It("says if packets are duplicates", func() {
		sendTime := time.Now()
		sentPackets.EXPECT().ReceivedPacket(gomock.Any()).AnyTimes()
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
		// Initial
		Expect(handler.IsPotentiallyDuplicate(3, protocol.EncryptionInitial)).To(BeFalse())
		Expect(handler.ReceivedPacket(3, protocol.ECNNon, protocol.EncryptionInitial, sendTime, true)).To(Succeed())
		Expect(handler.IsPotentiallyDuplicate(3, protocol.EncryptionInitial)).To(BeTrue())
		// Handshake
		Expect(handler.IsPotentiallyDuplicate(3, protocol.EncryptionHandshake)).To(BeFalse())
		Expect(handler.ReceivedPacket(3, protocol.ECNNon, protocol.EncryptionHandshake, sendTime, true)).To(Succeed())
		Expect(handler.IsPotentiallyDuplicate(3, protocol.EncryptionHandshake)).To(BeTrue())
		// 0-RTT
		Expect(handler.IsPotentiallyDuplicate(3, protocol.Encryption0RTT)).To(BeFalse())
		Expect(handler.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true)).To(Succeed())
		Expect(handler.IsPotentiallyDuplicate(3, protocol.Encryption0RTT)).To(BeTrue())
		// 1-RTT
		Expect(handler.IsPotentiallyDuplicate(3, protocol.Encryption1RTT)).To(BeTrue())
		Expect(handler.IsPotentiallyDuplicate(4, protocol.Encryption1RTT)).To(BeFalse())
		Expect(handler.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		Expect(handler.IsPotentiallyDuplicate(4, protocol.Encryption1RTT)).To(BeTrue())
	})
})
