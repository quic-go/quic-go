package qlog

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Types", func() {
	It("has a string representation for the category", func() {
		Expect(categoryConnectivity.String()).To(Equal("connectivity"))
		Expect(categoryTransport.String()).To(Equal("transport"))
		Expect(categoryRecovery.String()).To(Equal("recovery"))
		Expect(categorySecurity.String()).To(Equal("security"))
	})

	It("has a string representation for the packet type", func() {
		Expect(packetTypeInitial.String()).To(Equal("initial"))
		Expect(packetTypeHandshake.String()).To(Equal("handshake"))
		Expect(packetType0RTT.String()).To(Equal("0RTT"))
		Expect(packetType1RTT.String()).To(Equal("1RTT"))
		Expect(packetTypeRetry.String()).To(Equal("retry"))
		Expect(packetTypeVersionNegotiation.String()).To(Equal("version_negotiation"))
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
})
