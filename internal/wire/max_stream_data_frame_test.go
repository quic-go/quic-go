package wire

import (
	"bytes"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("MAX_STREAM_DATA frame", func() {
	Context("parsing", func() {
		It("accepts sample frame", func() {
			data := encodeVarInt(0xdeadbeef)                 // Stream ID
			data = append(data, encodeVarInt(0x12345678)...) // Offset
			b := bytes.NewReader(data)
			frame, err := parseMaxStreamDataFrame(b, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
			Expect(frame.MaximumStreamData).To(Equal(protocol.ByteCount(0x12345678)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := encodeVarInt(0xdeadbeef)                 // Stream ID
			data = append(data, encodeVarInt(0x12345678)...) // Offset
			b := bytes.NewReader(data)
			_, err := parseMaxStreamDataFrame(b, protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseMaxStreamDataFrame(bytes.NewReader(data[:i]), protocol.Version1)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("writing", func() {
		It("has proper length", func() {
			f := &MaxStreamDataFrame{
				StreamID:          0x1337,
				MaximumStreamData: 0xdeadbeef,
			}
			Expect(f.Length(protocol.Version1)).To(Equal(1 + quicvarint.Len(uint64(f.StreamID)) + quicvarint.Len(uint64(f.MaximumStreamData))))
		})

		It("writes a sample frame", func() {
			f := &MaxStreamDataFrame{
				StreamID:          0xdecafbad,
				MaximumStreamData: 0xdeadbeefcafe42,
			}
			expected := []byte{maxStreamDataFrameType}
			expected = append(expected, encodeVarInt(0xdecafbad)...)
			expected = append(expected, encodeVarInt(0xdeadbeefcafe42)...)
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal(expected))
		})
	})
})
