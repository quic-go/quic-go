package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PingFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x07})
			_, err := ParsePingFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(0))
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := PingFrame{}
			frame.Write(b, 10, 0)
			Expect(b.Bytes()).To(Equal([]byte{0x07}))
		})

		It("has the correct min length", func() {
			frame := PingFrame{}
			Expect(frame.MinLength()).To(Equal(protocol.ByteCount(1)))
		})
	})
})
