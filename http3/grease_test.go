package http3

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Grease", func() {
	It("generates a min greasing value", func() {
		got := Grease(0)
		Expect(got).To(Equal(uint64(GreaseMin)))
	})

	It("clamps to a max greasing value", func() {
		got := Grease(^uint64(0))
		Expect(got).To(Equal(uint64(GreaseMax)))
	})

	It("provides a value somewhere in the middle", func() {
		got := Grease(0x43)
		Expect(got).To(Equal(uint64(0x1f*0x43 + 0x21)))
	})
})
