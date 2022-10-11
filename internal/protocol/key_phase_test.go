package protocol

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Key Phases", func() {
	It("has undefined as its default value", func() {
		var k KeyPhaseBit
		Expect(k).To(Equal(KeyPhaseUndefined))
	})

	It("has the correct string representation", func() {
		Expect(KeyPhaseZero.String()).To(Equal("0"))
		Expect(KeyPhaseOne.String()).To(Equal("1"))
	})

	It("converts the key phase to the key phase bit", func() {
		Expect(KeyPhase(0).Bit()).To(Equal(KeyPhaseZero))
		Expect(KeyPhase(2).Bit()).To(Equal(KeyPhaseZero))
		Expect(KeyPhase(4).Bit()).To(Equal(KeyPhaseZero))
		Expect(KeyPhase(1).Bit()).To(Equal(KeyPhaseOne))
		Expect(KeyPhase(3).Bit()).To(Equal(KeyPhaseOne))
		Expect(KeyPhase(5).Bit()).To(Equal(KeyPhaseOne))
	})
})
