package ackhandler

import (
	"time"

	"github.com/golang/mock/gomock"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Received Packet Handler", func() {
	var handler ReceivedPacketHandler
	var sentPackets *MockSentPacketTracker

	BeforeEach(func() {
		sentPackets = NewMockSentPacketTracker(mockCtrl)
		handler = newReceivedPacketHandler(
			sentPackets,
			&congestion.RTTStats{},
			utils.DefaultLogger,
			protocol.VersionWhatever,
		)
	})

	It("generates ACKs for different packet number spaces", func() {
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
		sendTime := time.Now().Add(-time.Second)
		sentPackets.EXPECT().ReceivedPacket(protocol.EncryptionInitial).Times(2)
		sentPackets.EXPECT().ReceivedPacket(protocol.EncryptionHandshake).Times(2)
		sentPackets.EXPECT().ReceivedPacket(protocol.Encryption1RTT).Times(2)
		Expect(handler.ReceivedPacket(2, protocol.EncryptionInitial, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(1, protocol.EncryptionHandshake, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(5, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(3, protocol.EncryptionInitial, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(2, protocol.EncryptionHandshake, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(4, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		initialAck := handler.GetAckFrame(protocol.EncryptionInitial)
		Expect(initialAck).ToNot(BeNil())
		Expect(initialAck.AckRanges).To(HaveLen(1))
		Expect(initialAck.AckRanges[0]).To(Equal(wire.AckRange{Smallest: 2, Largest: 3}))
		Expect(initialAck.DelayTime).To(BeZero())
		handshakeAck := handler.GetAckFrame(protocol.EncryptionHandshake)
		Expect(handshakeAck).ToNot(BeNil())
		Expect(handshakeAck.AckRanges).To(HaveLen(1))
		Expect(handshakeAck.AckRanges[0]).To(Equal(wire.AckRange{Smallest: 1, Largest: 2}))
		Expect(handshakeAck.DelayTime).To(BeZero())
		oneRTTAck := handler.GetAckFrame(protocol.Encryption1RTT)
		Expect(oneRTTAck).ToNot(BeNil())
		Expect(oneRTTAck.AckRanges).To(HaveLen(1))
		Expect(oneRTTAck.AckRanges[0]).To(Equal(wire.AckRange{Smallest: 4, Largest: 5}))
		Expect(oneRTTAck.DelayTime).To(BeNumerically("~", time.Second, 50*time.Millisecond))
	})

	It("uses the same packet number space for 0-RTT and 1-RTT packets", func() {
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
		sentPackets.EXPECT().ReceivedPacket(protocol.Encryption0RTT)
		sentPackets.EXPECT().ReceivedPacket(protocol.Encryption1RTT)
		sendTime := time.Now().Add(-time.Second)
		Expect(handler.ReceivedPacket(2, protocol.Encryption0RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(3, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		ack := handler.GetAckFrame(protocol.Encryption1RTT)
		Expect(ack).ToNot(BeNil())
		Expect(ack.AckRanges).To(HaveLen(1))
		Expect(ack.AckRanges[0]).To(Equal(wire.AckRange{Smallest: 2, Largest: 3}))
	})

	It("rejects 0-RTT packets with higher packet numbers than 1-RTT packets", func() {
		sentPackets.EXPECT().ReceivedPacket(gomock.Any()).Times(3)
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
		sendTime := time.Now()
		Expect(handler.ReceivedPacket(10, protocol.Encryption0RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(11, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(12, protocol.Encryption0RTT, sendTime, true)).To(MatchError("received packet number 12 on a 0-RTT packet after receiving 11 on a 1-RTT packet"))
	})

	It("allows reordered 0-RTT packets", func() {
		sentPackets.EXPECT().ReceivedPacket(gomock.Any()).Times(3)
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
		sendTime := time.Now()
		Expect(handler.ReceivedPacket(10, protocol.Encryption0RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(12, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(11, protocol.Encryption0RTT, sendTime, true)).To(Succeed())
	})

	It("drops Initial packets", func() {
		sentPackets.EXPECT().ReceivedPacket(gomock.Any()).Times(2)
		sendTime := time.Now().Add(-time.Second)
		Expect(handler.ReceivedPacket(2, protocol.EncryptionInitial, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(1, protocol.EncryptionHandshake, sendTime, true)).To(Succeed())
		Expect(handler.GetAckFrame(protocol.EncryptionInitial)).ToNot(BeNil())
		handler.DropPackets(protocol.EncryptionInitial)
		Expect(handler.GetAckFrame(protocol.EncryptionInitial)).To(BeNil())
		Expect(handler.GetAckFrame(protocol.EncryptionHandshake)).ToNot(BeNil())
	})

	It("drops Handshake packets", func() {
		sentPackets.EXPECT().ReceivedPacket(gomock.Any()).Times(2)
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
		sendTime := time.Now().Add(-time.Second)
		Expect(handler.ReceivedPacket(1, protocol.EncryptionHandshake, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(2, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		Expect(handler.GetAckFrame(protocol.EncryptionHandshake)).ToNot(BeNil())
		handler.DropPackets(protocol.EncryptionInitial)
		Expect(handler.GetAckFrame(protocol.EncryptionHandshake)).To(BeNil())
		Expect(handler.GetAckFrame(protocol.Encryption1RTT)).ToNot(BeNil())
	})

	It("does nothing when dropping 0-RTT packets", func() {
		handler.DropPackets(protocol.Encryption0RTT)
	})

	It("drops old ACK ranges", func() {
		sentPackets.EXPECT().ReceivedPacket(gomock.Any()).AnyTimes()
		sendTime := time.Now()
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().Times(2)
		Expect(handler.ReceivedPacket(1, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		Expect(handler.ReceivedPacket(2, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		ack := handler.GetAckFrame(protocol.Encryption1RTT)
		Expect(ack).ToNot(BeNil())
		Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
		Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(2)))
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked()
		Expect(handler.ReceivedPacket(3, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().Return(protocol.PacketNumber(2))
		Expect(handler.ReceivedPacket(4, protocol.Encryption1RTT, sendTime, true)).To(Succeed())
		ack = handler.GetAckFrame(protocol.Encryption1RTT)
		Expect(ack).ToNot(BeNil())
		Expect(ack.LowestAcked()).To(Equal(protocol.PacketNumber(2)))
		Expect(ack.LargestAcked()).To(Equal(protocol.PacketNumber(4)))
	})
})
