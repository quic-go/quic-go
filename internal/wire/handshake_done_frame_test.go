package wire

import (
	"bytes"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HANDSHAKE_DONE frame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x1e})
			_, err := parseHandshakeDoneFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			_, err := parseHandshakeDoneFrame(bytes.NewReader(nil), protocol.VersionWhatever)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			frame := HandshakeDoneFrame{}
			b, err := frame.Append(nil, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal([]byte{0x1e}))
		})

		It("has the correct min length", func() {
			frame := HandshakeDoneFrame{}
			Expect(frame.Length(protocol.VersionWhatever)).To(Equal(protocol.ByteCount(1)))
		})
	})
})
