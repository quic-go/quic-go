package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("WindowUpdateFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x04, 0xEF, 0xBE, 0xAD, 0xDE, 0x44, 0x33, 0x22, 0x11, 0xAD, 0xFB, 0xCA, 0xDE})
			frame, err := ParseWindowUpdateFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xDEADBEEF)))
			Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0xDECAFBAD11223344)))
			Expect(b.Len()).To(Equal(0))
		})

		It("errors on EOFs", func() {
			data := []byte{0x04, 0xEF, 0xBE, 0xAD, 0xDE, 0x44, 0x33, 0x22, 0x11, 0xAD, 0xFB, 0xCA, 0xDE}
			_, err := ParseWindowUpdateFrame(bytes.NewReader(data))
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseWindowUpdateFrame(bytes.NewReader(data[0:i]))
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		It("has proper min length", func() {
			f := &WindowUpdateFrame{
				StreamID:   0x1337,
				ByteOffset: 0xDEADBEEF,
			}
			Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(13)))
		})

		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			f := &WindowUpdateFrame{
				StreamID:   0xDECAFBAD,
				ByteOffset: 0xDEADBEEFCAFE1337,
			}
			f.Write(b, 0)
			Expect(b.Bytes()).To(Equal([]byte{0x04, 0xAD, 0xFB, 0xCA, 0xDE, 0x37, 0x13, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE}))
		})
	})
})
