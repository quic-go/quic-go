package protocol

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Protocol", func() {
	Context("Long Header Packet Types", func() {
		It("has the correct string representation", func() {
			Expect(PacketTypeInitial.String()).To(Equal("Initial"))
			Expect(PacketTypeRetry.String()).To(Equal("Retry"))
			Expect(PacketTypeHandshake.String()).To(Equal("Handshake"))
			Expect(PacketType0RTT.String()).To(Equal("0-RTT Protected"))
			Expect(PacketType(10).String()).To(Equal("unknown packet type: 10"))
		})
	})

	Context("Key Phases", func() {
		It("has the correct string representation", func() {
			Expect(KeyPhaseZero.String()).To(Equal("0"))
			Expect(KeyPhaseOne.String()).To(Equal("1"))
		})

		It("returns the next key phase", func() {
			Expect(KeyPhaseZero.Next()).To(Equal(KeyPhaseOne))
			Expect(KeyPhaseOne.Next()).To(Equal(KeyPhaseZero))
		})
	})
})
