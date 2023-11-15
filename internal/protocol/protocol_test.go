package protocol

import (
	. "github.com/onsi/ginkgo/v2"
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

	It("converts ECN bits from the IP header wire to the correct types", func() {
		Expect(ParseECNHeaderBits(0)).To(Equal(ECNNon))
		Expect(ParseECNHeaderBits(0b00000010)).To(Equal(ECT0))
		Expect(ParseECNHeaderBits(0b00000001)).To(Equal(ECT1))
		Expect(ParseECNHeaderBits(0b00000011)).To(Equal(ECNCE))
		Expect(func() { ParseECNHeaderBits(0b1010101) }).To(Panic())
	})

	It("converts to IP header bits", func() {
		for _, v := range [...]ECN{ECNNon, ECT0, ECT1, ECNCE} {
			Expect(ParseECNHeaderBits(v.ToHeaderBits())).To(Equal(v))
		}
		Expect(func() { ECN(42).ToHeaderBits() }).To(Panic())
	})

	It("has a string representation for ECN", func() {
		Expect(ECNUnsupported.String()).To(Equal("ECN unsupported"))
		Expect(ECNNon.String()).To(Equal("Not-ECT"))
		Expect(ECT0.String()).To(Equal("ECT(0)"))
		Expect(ECT1.String()).To(Equal("ECT(1)"))
		Expect(ECNCE.String()).To(Equal("CE"))
		Expect(ECN(42).String()).To(Equal("invalid ECN value: 42"))
	})
})
