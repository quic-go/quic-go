package frames

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("StreamFrame", func() {
	Context("stream frames", func() {
		Context("when parsing", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x06, 0xA4, 0x03})
				frame, err := ParseStopWaitingFrame(b, 1)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.Entropy).To(Equal(byte(0xA4)))
				Expect(frame.LeastUnackedDelta).To(Equal(uint64(0x03)))
			})
		})
	})
})
