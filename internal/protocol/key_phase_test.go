package protocol

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Key Phases", func() {
	It("has the correct string representation", func() {
		Expect(KeyPhaseZero.String()).To(Equal("0"))
		Expect(KeyPhaseOne.String()).To(Equal("1"))
	})

	It("returns the next key phase", func() {
		Expect(KeyPhaseZero.Next()).To(Equal(KeyPhaseOne))
		Expect(KeyPhaseOne.Next()).To(Equal(KeyPhaseZero))
	})
})
