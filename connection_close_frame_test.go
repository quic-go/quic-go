package quic

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AckFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x40, 0x19, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x4e, 0x6f, 0x20, 0x72, 0x65, 0x63, 0x65, 0x6e, 0x74, 0x20, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x2e})
			frame, err := ParseConnectionCloseFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.ErrorCode).To(Equal(uint32(0x19)))
			Expect(frame.ReasonPhrase).To(Equal("No recent network activity."))
			Expect(b.Len()).To(Equal(0))
		})

		It("parses a frame without a reason phrase", func() {
			b := bytes.NewReader([]byte{0x02, 0xAD, 0xFB, 0xCA, 0xDE, 0x00, 0x00})
			frame, err := ParseConnectionCloseFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.ErrorCode).To(Equal(uint32(0xDECAFBAD)))
			Expect(len(frame.ReasonPhrase)).To(Equal(0))
			Expect(b.Len()).To(Equal(0))
		})
	})
})
