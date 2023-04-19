package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PING frame", func() {
	Context("when writing", func() {
		It("writes a sample frame", func() {
			frame := PingFrame{}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal([]byte{0x1}))
		})

		It("has the correct length", func() {
			frame := PingFrame{}
			Expect(frame.Length(0)).To(Equal(protocol.ByteCount(1)))
		})
	})
})
