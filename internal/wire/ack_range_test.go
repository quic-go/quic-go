package wire

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ACK range", func() {
	It("returns the length", func() {
		Expect(AckRange{First: 10, Last: 10}.Len()).To(BeEquivalentTo(1))
		Expect(AckRange{First: 10, Last: 13}.Len()).To(BeEquivalentTo(4))
	})
})
