package wire

import (
	"bytes"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("MAX_DATA frame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			data := []byte{0x10}
			data = append(data, encodeVarInt(0xdecafbad123456)...) // byte offset
			b := bytes.NewReader(data)
			frame, err := parseMaxDataFrame(b, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.MaximumData).To(Equal(protocol.ByteCount(0xdecafbad123456)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x10}
			data = append(data, encodeVarInt(0xdecafbad1234567)...) // byte offset
			_, err := parseMaxDataFrame(bytes.NewReader(data), protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseMaxDataFrame(bytes.NewReader(data[0:i]), protocol.Version1)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("writing", func() {
		It("has proper length", func() {
			f := &MaxDataFrame{
				MaximumData: 0xdeadbeef,
			}
			Expect(f.Length(protocol.Version1)).To(Equal(1 + quicvarint.Len(0xdeadbeef)))
		})

		It("writes a MAX_DATA frame", func() {
			f := &MaxDataFrame{
				MaximumData: 0xdeadbeefcafe,
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x10}
			expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
			Expect(b).To(Equal(expected))
		})
	})
})
