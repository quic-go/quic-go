package protocol

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Encryption Level", func() {
	It("has the correct string representation", func() {
		Expect(EncryptionUnspecified.String()).To(Equal("unknown"))
		Expect(EncryptionInitial.String()).To(Equal("Initial"))
		Expect(EncryptionHandshake.String()).To(Equal("Handshake"))
		Expect(Encryption0RTT.String()).To(Equal("0-RTT"))
		Expect(Encryption1RTT.String()).To(Equal("1-RTT"))
	})
})
