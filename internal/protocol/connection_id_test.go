package protocol

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Connection ID generation", func() {
	It("generates random connection IDs", func() {
		c1, err := GenerateConnectionID()
		Expect(err).ToNot(HaveOccurred())
		Expect(c1).ToNot(BeZero())
		c2, err := GenerateConnectionID()
		Expect(err).ToNot(HaveOccurred())
		Expect(c1).ToNot(Equal(c2))
	})

	It("says if connection IDs are equal", func() {
		c1 := ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		c2 := ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
		Expect(c1.Equal(c1)).To(BeTrue())
		Expect(c2.Equal(c2)).To(BeTrue())
		Expect(c1.Equal(c2)).To(BeFalse())
		Expect(c2.Equal(c1)).To(BeFalse())
	})
})
