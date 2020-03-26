package qlog

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Types", func() {
	It("has a string representation for the owner", func() {
		Expect(ownerLocal.String()).To(Equal("local"))
		Expect(ownerRemote.String()).To(Equal("remote"))
	})

	It("has a string representation for the category", func() {
		Expect(categoryConnectivity.String()).To(Equal("connectivity"))
		Expect(categoryTransport.String()).To(Equal("transport"))
		Expect(categoryRecovery.String()).To(Equal("recovery"))
		Expect(categorySecurity.String()).To(Equal("security"))
	})

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

	It("has a string representation for the key type", func() {
		Expect(encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveClient).String()).To(Equal("client_initial_secret"))
		Expect(encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveServer).String()).To(Equal("server_initial_secret"))
		Expect(encLevelToKeyType(protocol.EncryptionHandshake, protocol.PerspectiveClient).String()).To(Equal("client_handshake_secret"))
		Expect(encLevelToKeyType(protocol.EncryptionHandshake, protocol.PerspectiveServer).String()).To(Equal("server_handshake_secret"))
		Expect(encLevelToKeyType(protocol.Encryption0RTT, protocol.PerspectiveClient).String()).To(Equal("client_0rtt_secret"))
		Expect(encLevelToKeyType(protocol.Encryption0RTT, protocol.PerspectiveServer).String()).To(Equal("server_0rtt_secret"))
		Expect(encLevelToKeyType(protocol.Encryption1RTT, protocol.PerspectiveClient).String()).To(Equal("client_1rtt_secret"))
		Expect(encLevelToKeyType(protocol.Encryption1RTT, protocol.PerspectiveServer).String()).To(Equal("server_1rtt_secret"))
	})

	It("has a string representation for the key update trigger", func() {
		Expect(keyUpdateTLS.String()).To(Equal("tls"))
		Expect(keyUpdateRemote.String()).To(Equal("remote_update"))
		Expect(keyUpdateLocal.String()).To(Equal("local_update"))
	})

	It("has a string representation for the packet drop reason", func() {
		Expect(PacketDropKeyUnavailable.String()).To(Equal("key_unavailable"))
		Expect(PacketDropUnknownConnectionID.String()).To(Equal("unknown_connection_id"))
		Expect(PacketDropHeaderParseError.String()).To(Equal("header_parse_error"))
		Expect(PacketDropPayloadDecryptError.String()).To(Equal("payload_decrypt_error"))
		Expect(PacketDropProtocolViolation.String()).To(Equal("protocol_violation"))
		Expect(PacketDropDOSPrevention.String()).To(Equal("dos_prevention"))
		Expect(PacketDropUnsupportedVersion.String()).To(Equal("unsupported_version"))
	})
})
