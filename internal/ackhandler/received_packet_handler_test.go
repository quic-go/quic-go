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
		now := time.Now()
		Expect(handler.ReceivedPacket(2, protocol.EncryptionInitial, now, true)).To(Succeed())
		Expect(handler.ReceivedPacket(1, protocol.EncryptionHandshake, now, true)).To(Succeed())
		Expect(handler.ReceivedPacket(5, protocol.Encryption1RTT, now, true)).To(Succeed())
		Expect(handler.ReceivedPacket(3, protocol.EncryptionInitial, now, true)).To(Succeed())
		Expect(handler.ReceivedPacket(2, protocol.EncryptionHandshake, now, true)).To(Succeed())
		Expect(handler.ReceivedPacket(4, protocol.Encryption1RTT, now, true)).To(Succeed())
		initialAck := handler.GetAckFrame(protocol.EncryptionInitial)
		Expect(initialAck).ToNot(BeNil())
		Expect(initialAck.AckRanges).To(HaveLen(1))
		Expect(initialAck.AckRanges[0]).To(Equal(wire.AckRange{Smallest: 2, Largest: 3}))
		handshakeAck := handler.GetAckFrame(protocol.EncryptionHandshake)
		Expect(handshakeAck).ToNot(BeNil())
		Expect(handshakeAck.AckRanges).To(HaveLen(1))
		Expect(handshakeAck.AckRanges[0]).To(Equal(wire.AckRange{Smallest: 1, Largest: 2}))
		oneRTTAck := handler.GetAckFrame(protocol.Encryption1RTT)
		Expect(oneRTTAck).ToNot(BeNil())
		Expect(oneRTTAck.AckRanges).To(HaveLen(1))
		Expect(oneRTTAck.AckRanges[0]).To(Equal(wire.AckRange{Smallest: 4, Largest: 5}))
	})
})
