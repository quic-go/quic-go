package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NEW_CONNECTION_ID frame", func() {
	Context("when parsing", func() {
		It("accepts a sample frame", func() {
			data := []byte{0x19}
			data = append(data, encodeVarInt(0xdeadbeef)...) // sequence number
			b := bytes.NewReader(data)
			frame, err := parseRetireConnectionIDFrame(b, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.SequenceNumber).To(Equal(uint64(0xdeadbeef)))
		})

		It("errors on EOFs", func() {
			data := []byte{0x18}
			data = append(data, encodeVarInt(0xdeadbeef)...) // sequence number
			_, err := parseRetireConnectionIDFrame(bytes.NewReader(data), protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseRetireConnectionIDFrame(bytes.NewReader(data[0:i]), protocol.Version1)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			frame := &RetireConnectionIDFrame{SequenceNumber: 0x1337}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x19}
			expected = append(expected, encodeVarInt(0x1337)...)
			Expect(b).To(Equal(expected))
		})

		It("has the correct length", func() {
			frame := &RetireConnectionIDFrame{SequenceNumber: 0xdecafbad}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(HaveLen(int(frame.Length(protocol.Version1))))
		})
	})
})
