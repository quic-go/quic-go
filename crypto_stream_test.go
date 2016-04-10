package quic

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CryptoStream", func() {
	Context("when parsing", func() {
		It("parses sample CHLO message", func() {
			tag, msg, err := ParseCryptoMessage(sampleCHLO)
			Expect(err).ToNot(HaveOccurred())
			Expect(tag).To(Equal(TagCHLO))
			Expect(msg).To(Equal(sampleCHLOMap))
		})
	})

	Context("when writing", func() {
		It("writes sample message", func() {
			b := &bytes.Buffer{}
			WriteCryptoMessage(b, TagCHLO, sampleCHLOMap)
			Expect(b.Bytes()).To(Equal(sampleCHLO))
		})
	})
})
