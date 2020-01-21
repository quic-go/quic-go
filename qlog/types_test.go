package qlog

import (
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
})
