package handshake

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Handshake Message", func() {
	Context("when parsing", func() {
		It("parses sample CHLO message", func() {
			tag, msg, err := ParseHandshakeMessage(bytes.NewReader(sampleCHLO))
			Expect(err).ToNot(HaveOccurred())
			Expect(tag).To(Equal(TagCHLO))
			Expect(msg).To(Equal(sampleCHLOMap))
		})
	})

	Context("when writing", func() {
		It("writes sample message", func() {
			b := &bytes.Buffer{}
			WriteHandshakeMessage(b, TagCHLO, sampleCHLOMap)
			Expect(b.Bytes()).To(Equal(sampleCHLO))
		})
	})
})
