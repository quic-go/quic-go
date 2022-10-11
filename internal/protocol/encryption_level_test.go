package protocol

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Encryption Level", func() {
	It("doesn't use 0 as a value", func() {
		// 0 is used in some tests
		Expect(EncryptionInitial * EncryptionHandshake * Encryption0RTT * Encryption1RTT).ToNot(BeZero())
	})

	It("has the correct string representation", func() {
		Expect(EncryptionInitial.String()).To(Equal("Initial"))
		Expect(EncryptionHandshake.String()).To(Equal("Handshake"))
		Expect(Encryption0RTT.String()).To(Equal("0-RTT"))
		Expect(Encryption1RTT.String()).To(Equal("1-RTT"))
	})
})
