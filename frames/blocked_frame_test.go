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
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := BlockedFrame{StreamID: 0x1337}
			frame.Write(b, 10, protocol.PacketNumberLen6, 0)
			Expect(b.Bytes()).To(Equal([]byte{0x05, 0x37, 0x13, 0x0, 0x0}))
		})

		It("has the correct min length", func() {
			frame := BlockedFrame{StreamID: 3}
			Expect(frame.MinLength()).To(Equal(5))
		})
	})
})
