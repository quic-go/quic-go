package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("BlockedFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x05, 0xEF, 0xBE, 0xAD, 0xDE})
			frame, err := ParseBlockedFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xDEADBEEF)))
		})

		It("errors on EOFs", func() {
			data := []byte{0x05, 0xEF, 0xBE, 0xAD, 0xDE}
			_, err := ParseBlockedFrame(bytes.NewReader(data))
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseBlockedFrame(bytes.NewReader(data[0:i]))
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := BlockedFrame{StreamID: 0x1337}
			frame.Write(b, 0)
			Expect(b.Bytes()).To(Equal([]byte{0x05, 0x37, 0x13, 0x0, 0x0}))
		})

		It("writes a connection-level Blocked", func() {
			b := &bytes.Buffer{}
			frame := BlockedFrame{StreamID: 0}
			frame.Write(b, 0)
			Expect(b.Bytes()).To(Equal([]byte{0x05, 0, 0, 0, 0}))
		})

		It("has the correct min length", func() {
			frame := BlockedFrame{StreamID: 3}
			Expect(frame.MinLength(0)).To(Equal(protocol.ByteCount(5)))
		})
	})
})
