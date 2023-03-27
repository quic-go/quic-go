package wire

import (
	"bytes"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("STOP_SENDING frame", func() {
	Context("when parsing", func() {
		It("parses a sample frame", func() {
			data := encodeVarInt(0xdecafbad)             // stream ID
			data = append(data, encodeVarInt(0x1337)...) // error code
			b := bytes.NewReader(data)
			frame, err := parseStopSendingFrame(b, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdecafbad)))
			Expect(frame.ErrorCode).To(Equal(qerr.StreamErrorCode(0x1337)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := encodeVarInt(0xdecafbad)               // stream ID
			data = append(data, encodeVarInt(0x123456)...) // error code
			b := bytes.NewReader(data)
			_, err := parseStopSendingFrame(b, protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseStopSendingFrame(bytes.NewReader(data[:i]), protocol.Version1)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("when writing", func() {
		It("writes", func() {
			frame := &StopSendingFrame{
				StreamID:  0xdeadbeefcafe,
				ErrorCode: 0xdecafbad,
			}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{stopSendingFrameType}
			expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
			expected = append(expected, encodeVarInt(0xdecafbad)...)
			Expect(b).To(Equal(expected))
		})

		It("has the correct min length", func() {
			frame := &StopSendingFrame{
				StreamID:  0xdeadbeef,
				ErrorCode: 0x1234567,
			}
			Expect(frame.Length(protocol.Version1)).To(Equal(1 + quicvarint.Len(0xdeadbeef) + quicvarint.Len(0x1234567)))
		})
	})
})
