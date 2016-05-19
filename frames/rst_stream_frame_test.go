package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("RstStreamFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x01, 0xEF, 0xBE, 0xAD, 0xDE, 0x44, 0x33, 0x22, 0x11, 0xAD, 0xFB, 0xCA, 0xDE, 0x34, 0x12, 0x37, 0x13})
			frame, err := ParseRstStreamFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xDEADBEEF)))
			Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0xDECAFBAD11223344)))
			Expect(frame.ErrorCode).To(Equal(uint32(0x13371234)))
		})
	})

	Context("when writing", func() {
		It("writes a sample RstStreamFrame", func() {
			frame := RstStreamFrame{
				StreamID:   0x1337,
				ByteOffset: 0x11223344DECAFBAD,
				ErrorCode:  0xDEADBEEF,
			}
			b := &bytes.Buffer{}
			frame.Write(b, 0)
			Expect(b.Bytes()).To(Equal([]byte{0x01, 0x37, 0x13, 0, 0, 0xAD, 0xFB, 0xCA, 0xDE, 0x44, 0x33, 0x22, 0x11, 0xEF, 0xBE, 0xAD, 0xDE}))
		})

		It("has the correct min length", func() {
			rst := RstStreamFrame{
				StreamID:   0x1337,
				ByteOffset: 0x1000,
				ErrorCode:  0xDE,
			}
			Expect(rst.MinLength()).To(Equal(protocol.ByteCount(17)))
		})
	})
})
