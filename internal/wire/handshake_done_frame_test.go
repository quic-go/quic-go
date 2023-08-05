package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HANDSHAKE_DONE frame", func() {
	Context("when writing", func() {
		It("writes a sample frame", func() {
			frame := HandshakeDoneFrame{}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal([]byte{handshakeDoneFrameType}))
		})

		It("has the correct min length", func() {
			frame := HandshakeDoneFrame{}
			Expect(frame.Length(protocol.Version1)).To(Equal(protocol.ByteCount(1)))
		})
	})
})
