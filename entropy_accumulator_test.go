package quic

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("EntropyAccumulator", func() {
	It("initializes as zero", func() {
		var e EntropyAccumulator
		Expect(e.Get()).To(BeZero())
	})

	It("adds entropy", func() {
		var e EntropyAccumulator
		e.Add(9, true)
		Expect(e.Get()).To(Equal(byte(0x02)))
	})

	It("doesn't add entropy for zero entropy flags", func() {
		var e EntropyAccumulator
		e.Add(9, false)
		Expect(e.Get()).To(BeZero())
	})
})
