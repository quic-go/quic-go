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

var _ = Describe("Received Packet Handler", func() {
	var handler ReceivedPacketHandler

	BeforeEach(func() {
		handler = NewReceivedPacketHandler(
			&congestion.RTTStats{},
			utils.DefaultLogger,
			protocol.VersionWhatever,
		)
	})

	It("generates ACKs for different packet number spaces", func() {
		sendTime := time.Now().Add(-time.Second)
		handler.ReceivedPacket(2, protocol.EncryptionInitial, sendTime, true)
		handler.ReceivedPacket(1, protocol.EncryptionHandshake, sendTime, true)
		handler.ReceivedPacket(5, protocol.Encryption1RTT, sendTime, true)
		handler.ReceivedPacket(3, protocol.EncryptionInitial, sendTime, true)
		handler.ReceivedPacket(2, protocol.EncryptionHandshake, sendTime, true)
		handler.ReceivedPacket(4, protocol.Encryption1RTT, sendTime, true)
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

	It("drops Initial packets", func() {
		sendTime := time.Now().Add(-time.Second)
		handler.ReceivedPacket(2, protocol.EncryptionInitial, sendTime, true)
		handler.ReceivedPacket(1, protocol.EncryptionHandshake, sendTime, true)
		Expect(handler.GetAckFrame(protocol.EncryptionInitial)).ToNot(BeNil())
		handler.DropPackets(protocol.EncryptionInitial)
		Expect(handler.GetAckFrame(protocol.EncryptionInitial)).To(BeNil())
		Expect(handler.GetAckFrame(protocol.EncryptionHandshake)).ToNot(BeNil())
	})

	It("drops Handshake packets", func() {
		sendTime := time.Now().Add(-time.Second)
		handler.ReceivedPacket(1, protocol.EncryptionHandshake, sendTime, true)
		handler.ReceivedPacket(2, protocol.Encryption1RTT, sendTime, true)
		Expect(handler.GetAckFrame(protocol.EncryptionHandshake)).ToNot(BeNil())
		handler.DropPackets(protocol.EncryptionInitial)
		Expect(handler.GetAckFrame(protocol.EncryptionHandshake)).To(BeNil())
		Expect(handler.GetAckFrame(protocol.Encryption1RTT)).ToNot(BeNil())
	})
})
