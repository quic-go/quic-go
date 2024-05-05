package wire

import (
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("DATA_BLOCKED frame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			data := encodeVarInt(0x12345678)
			frame, l, err := parseDataBlockedFrame(data, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.MaximumData).To(Equal(protocol.ByteCount(0x12345678)))
			Expect(l).To(Equal(len(data)))
		})

		It("errors on EOFs", func() {
			data := encodeVarInt(0x12345678)
			_, l, err := parseDataBlockedFrame(data, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(l).To(Equal(len(data)))
			for i := range data {
				_, _, err := parseDataBlockedFrame(data[:i], protocol.Version1)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			frame := DataBlockedFrame{MaximumData: 0xdeadbeef}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{dataBlockedFrameType}
			expected = append(expected, encodeVarInt(0xdeadbeef)...)
			Expect(b).To(Equal(expected))
		})

		It("has the correct min length", func() {
			frame := DataBlockedFrame{MaximumData: 0x12345}
			Expect(frame.Length(protocol.Version1)).To(BeEquivalentTo(1 + quicvarint.Len(0x12345)))
		})
	})
})
