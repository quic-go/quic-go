package logging

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Types", func() {
	It("has a string representation for the packet type", func() {
		Expect(PacketTypeInitial.String()).To(Equal("initial"))
		Expect(PacketTypeHandshake.String()).To(Equal("handshake"))
		Expect(PacketType0RTT.String()).To(Equal("0RTT"))
		Expect(PacketType1RTT.String()).To(Equal("1RTT"))
		Expect(PacketTypeStatelessReset.String()).To(Equal("stateless_reset"))
		Expect(PacketTypeRetry.String()).To(Equal("retry"))
		Expect(PacketTypeVersionNegotiation.String()).To(Equal("version_negotiation"))
		Expect(PacketTypeNotDetermined.String()).To(BeEmpty())
	})

	It("has a string representation for the packet drop reason", func() {
		Expect(PacketDropKeyUnavailable.String()).To(Equal("key_unavailable"))
		Expect(PacketDropUnknownConnectionID.String()).To(Equal("unknown_connection_id"))
		Expect(PacketDropHeaderParseError.String()).To(Equal("header_parse_error"))
		Expect(PacketDropPayloadDecryptError.String()).To(Equal("payload_decrypt_error"))
		Expect(PacketDropProtocolViolation.String()).To(Equal("protocol_violation"))
		Expect(PacketDropDOSPrevention.String()).To(Equal("dos_prevention"))
		Expect(PacketDropUnsupportedVersion.String()).To(Equal("unsupported_version"))
		Expect(PacketDropUnexpectedPacket.String()).To(Equal("unexpected_packet"))
		Expect(PacketDropUnexpectedSourceConnectionID.String()).To(Equal("unexpected_source_connection_id"))
		Expect(PacketDropUnexpectedVersion.String()).To(Equal("unexpected_version"))
	})

	It("has a string representation for the timer type", func() {
		Expect(TimerTypeACK.String()).To(Equal("ack"))
		Expect(TimerTypePTO.String()).To(Equal("pto"))
	})

	It("has a string representation for the close reason", func() {
		Expect(CloseReasonHandshakeTimeout.String()).To(Equal("handshake_timeout"))
		Expect(CloseReasonIdleTimeout.String()).To(Equal("idle_timeout"))
	})
})
