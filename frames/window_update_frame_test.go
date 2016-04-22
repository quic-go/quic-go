package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("WindowUpdateFrame", func() {
	Context("window update frames", func() {
		Context("when parsing", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x04, 0xEF, 0xBE, 0xAD, 0xDE, 0x44, 0x33, 0x22, 0x11, 0xAD, 0xFB, 0xCA, 0xDE})
				frame, err := ParseWindowUpdateFrame(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(protocol.StreamID(0xDEADBEEF)))
				Expect(frame.ByteOffset).To(Equal(uint64(0xDECAFBAD11223344)))
				Expect(b.Len()).To(Equal(0))
			})
		})
	})
})
