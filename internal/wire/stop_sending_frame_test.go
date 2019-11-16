package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("STOP_SENDING frame", func() {
	Context("when parsing", func() {
		It("parses a sample frame", func() {
			data := []byte{0x5}
			data = append(data, encodeVarInt(0xdecafbad)...) // stream ID
			data = append(data, encodeVarInt(0x1337)...)     // error code
			b := bytes.NewReader(data)
			frame, err := parseStopSendingFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdecafbad)))
			Expect(frame.ErrorCode).To(Equal(protocol.ApplicationErrorCode(0x1337)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x5}
			data = append(data, encodeVarInt(0xdecafbad)...) // stream ID
			data = append(data, encodeVarInt(0x123456)...)   // error code
			_, err := parseStopSendingFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseStopSendingFrame(bytes.NewReader(data[:i]), versionIETFFrames)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		It("writes", func() {
			frame := &StopSendingFrame{
				StreamID:  0xdeadbeefcafe,
				ErrorCode: 0xdecafbad,
			}
			buf := &bytes.Buffer{}
			Expect(frame.Write(buf, versionIETFFrames)).To(Succeed())
			expected := []byte{0x5}
			expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
			expected = append(expected, encodeVarInt(0xdecafbad)...)
			Expect(buf.Bytes()).To(Equal(expected))
		})

		It("has the correct min length", func() {
			frame := &StopSendingFrame{
				StreamID:  0xdeadbeef,
				ErrorCode: 0x1234567,
			}
			Expect(frame.Length(versionIETFFrames)).To(Equal(1 + utils.VarIntLen(0xdeadbeef) + utils.VarIntLen(0x1234567)))
		})
	})
})
