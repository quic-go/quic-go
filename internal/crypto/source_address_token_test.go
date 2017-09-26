package crypto

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Source Address Tokens", func() {
	It("should generate the encryption key", func() {
		Expect(deriveKey([]byte("TESTING"))).To(Equal([]byte{0xee, 0x71, 0x18, 0x9, 0xfd, 0xb8, 0x9a, 0x79, 0x19, 0xfc, 0x5e, 0x1a, 0x97, 0x20, 0xb2, 0x6}))
	})

	Context("tokens", func() {
		var source *stkSource

		BeforeEach(func() {
			sourceI, err := NewStkSource()
			source = sourceI.(*stkSource)
			Expect(err).NotTo(HaveOccurred())
		})

		It("serializes", func() {
			token, err := source.NewToken([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			data, err := source.DecodeToken(token)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal([]byte("foobar")))
		})

		It("rejects invalid tokens", func() {
			_, err := source.DecodeToken([]byte("invalid source address token"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("message authentication failed"))
		})

		It("rejects tokens of wrong size", func() {
			_, err := source.DecodeToken(nil)
			Expect(err).To(MatchError("STK too short: 0"))
		})
	})
})
