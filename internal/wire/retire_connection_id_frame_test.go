package wire

import (
	"io"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NEW_CONNECTION_ID frame", func() {
	Context("when parsing", func() {
		It("accepts a sample frame", func() {
			data := encodeVarInt(0xdeadbeef) // sequence number
			frame, l, err := parseRetireConnectionIDFrame(data, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.SequenceNumber).To(Equal(uint64(0xdeadbeef)))
			Expect(l).To(Equal(len(data)))
		})

		It("errors on EOFs", func() {
			data := encodeVarInt(0xdeadbeef) // sequence number
			_, l, err := parseRetireConnectionIDFrame(data, protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			Expect(l).To(Equal(len(data)))
			for i := range data {
				_, _, err := parseRetireConnectionIDFrame(data[:i], protocol.Version1)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			frame := &RetireConnectionIDFrame{SequenceNumber: 0x1337}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{retireConnectionIDFrameType}
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
