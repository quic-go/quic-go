package ackhandler

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("EntropyAccumulator", func() {
	It("initializes as zero", func() {
		var e EntropyAccumulator
		Expect(e.Get()).To(BeZero())
	})

	Context("Add", func() {
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

	Context("Substract", func() {
		It("calculates the correct entropy", func() {
			var e1 EntropyAccumulator
			e1.Add(3, true)

			var e2 EntropyAccumulator
			e2.Add(1, true)
			e2.Add(3, true)
			e2.Substract(1, true)

			Expect(e1).To(Equal(e2))
		})
	})
})
