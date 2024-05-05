package wire

import (
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("MAX_DATA frame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			data := encodeVarInt(0xdecafbad123456) // byte offset
			frame, l, err := parseMaxDataFrame(data, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.MaximumData).To(Equal(protocol.ByteCount(0xdecafbad123456)))
			Expect(l).To(Equal(len(data)))
		})

		It("errors on EOFs", func() {
			data := encodeVarInt(0xdecafbad1234567) // byte offset
			_, l, err := parseMaxDataFrame(data, protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			Expect(l).To(Equal(len(data)))
			for i := range data {
				_, _, err := parseMaxDataFrame(data[:i], protocol.Version1)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("writing", func() {
		It("has proper length", func() {
			f := &MaxDataFrame{
				MaximumData: 0xdeadbeef,
			}
			Expect(f.Length(protocol.Version1)).To(BeEquivalentTo(1 + quicvarint.Len(0xdeadbeef)))
		})

		It("writes a MAX_DATA frame", func() {
			f := &MaxDataFrame{
				MaximumData: 0xdeadbeefcafe,
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{maxDataFrameType}
			expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
			Expect(b).To(Equal(expected))
		})
	})
})
