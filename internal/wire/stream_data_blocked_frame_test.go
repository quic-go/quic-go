package wire

import (
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("STREAM_DATA_BLOCKED frame", func() {
	Context("parsing", func() {
		It("accepts sample frame", func() {
			data := encodeVarInt(0xdeadbeef)                 // stream ID
			data = append(data, encodeVarInt(0xdecafbad)...) // offset
			frame, l, err := parseStreamDataBlockedFrame(data, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
			Expect(frame.MaximumStreamData).To(Equal(protocol.ByteCount(0xdecafbad)))
			Expect(l).To(Equal(len(data)))
		})

		It("errors on EOFs", func() {
			data := encodeVarInt(0xdeadbeef)
			data = append(data, encodeVarInt(0xc0010ff)...)
			_, l, err := parseStreamDataBlockedFrame(data, protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			Expect(l).To(Equal(len(data)))
			for i := range data {
				_, _, err := parseStreamDataBlockedFrame(data[:i], protocol.Version1)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("writing", func() {
		It("has proper min length", func() {
			f := &StreamDataBlockedFrame{
				StreamID:          0x1337,
				MaximumStreamData: 0xdeadbeef,
			}
			Expect(f.Length(0)).To(BeEquivalentTo(1 + quicvarint.Len(0x1337) + quicvarint.Len(0xdeadbeef)))
		})

		It("writes a sample frame", func() {
			f := &StreamDataBlockedFrame{
				StreamID:          0xdecafbad,
				MaximumStreamData: 0x1337,
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{streamDataBlockedFrameType}
			expected = append(expected, encodeVarInt(uint64(f.StreamID))...)
			expected = append(expected, encodeVarInt(uint64(f.MaximumStreamData))...)
			Expect(b).To(Equal(expected))
		})
	})
})
