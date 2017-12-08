package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("STREAM frame (for IETF QUIC)", func() {
	Context("when parsing", func() {
		It("parses a frame with OFF bit", func() {
			data := []byte{0x10 ^ 0x4}
			data = append(data, encodeVarInt(0x12345)...)    // stream ID
			data = append(data, encodeVarInt(0xdecafbad)...) // offset
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			frame, err := ParseStreamFrame(r, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0x12345)))
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(frame.FinBit).To(BeFalse())
			Expect(frame.Offset).To(Equal(protocol.ByteCount(0xdecafbad)))
			Expect(r.Len()).To(BeZero())
		})

		It("respects the LEN when parsing the frame", func() {
			data := []byte{0x10 ^ 0x2}
			data = append(data, encodeVarInt(0x12345)...) // stream ID
			data = append(data, encodeVarInt(4)...)       // data length
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			frame, err := ParseStreamFrame(r, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0x12345)))
			Expect(frame.Data).To(Equal([]byte("foob")))
			Expect(frame.FinBit).To(BeFalse())
			Expect(frame.Offset).To(BeZero())
			Expect(r.Len()).To(Equal(2))
		})

		It("parses a frame with FIN bit", func() {
			data := []byte{0x10 ^ 0x1}
			data = append(data, encodeVarInt(9)...) // stream ID
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			frame, err := ParseStreamFrame(r, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(9)))
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(frame.FinBit).To(BeTrue())
			Expect(frame.Offset).To(BeZero())
			Expect(r.Len()).To(BeZero())
		})

		It("rejects empty frames than don't have the FIN bit set", func() {
			data := []byte{0x10}
			data = append(data, encodeVarInt(0x1337)...) // stream ID
			r := bytes.NewReader(data)
			_, err := ParseStreamFrame(r, versionIETFFrames)
			Expect(err).To(MatchError(qerr.EmptyStreamFrameNoFin))
		})

		It("rejects frames that overflow the maximum offset", func() {
			data := []byte{0x10 ^ 0x4}
			data = append(data, encodeVarInt(0x12345)...)                         // stream ID
			data = append(data, encodeVarInt(uint64(protocol.MaxByteCount-5))...) // offset
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			_, err := ParseStreamFrame(r, versionIETFFrames)
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidStreamData, "data overflows maximum offset")))
		})

		It("errors on EOFs", func() {
			data := []byte{0x10 ^ 0x4 ^ 0x2}
			data = append(data, encodeVarInt(0x12345)...)    // stream ID
			data = append(data, encodeVarInt(0xdecafbad)...) // offset
			data = append(data, encodeVarInt(6)...)          // data length
			data = append(data, []byte("foobar")...)
			_, err := ParseStreamFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseStreamFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		It("writes a frame without offset", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Data:     []byte("foobar"),
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x10}
			expected = append(expected, encodeVarInt(0x1337)...) // stream ID
			expected = append(expected, []byte("foobar")...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("writes a frame with offset", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Offset:   0x123456,
				Data:     []byte("foobar"),
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x10 ^ 0x4}
			expected = append(expected, encodeVarInt(0x1337)...)   // stream ID
			expected = append(expected, encodeVarInt(0x123456)...) // offset
			expected = append(expected, []byte("foobar")...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("writes a frame with FIN bit", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Offset:   0x123456,
				FinBit:   true,
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x10 ^ 0x4 ^ 0x1}
			expected = append(expected, encodeVarInt(0x1337)...)   // stream ID
			expected = append(expected, encodeVarInt(0x123456)...) // offset
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("writes a frame with data length", func() {
			f := &StreamFrame{
				StreamID:       0x1337,
				Data:           []byte("foobar"),
				DataLenPresent: true,
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x10 ^ 0x2}
			expected = append(expected, encodeVarInt(0x1337)...) // stream ID
			expected = append(expected, encodeVarInt(6)...)      // data length
			expected = append(expected, []byte("foobar")...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("writes a frame with data length and offset", func() {
			f := &StreamFrame{
				StreamID:       0x1337,
				Data:           []byte("foobar"),
				DataLenPresent: true,
				Offset:         0x123456,
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x10 ^ 0x4 ^ 0x2}
			expected = append(expected, encodeVarInt(0x1337)...)   // stream ID
			expected = append(expected, encodeVarInt(0x123456)...) // offset
			expected = append(expected, encodeVarInt(6)...)        // data length
			expected = append(expected, []byte("foobar")...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("refuses to write an empty frame without FIN", func() {
			f := &StreamFrame{
				StreamID: 0x42,
				Offset:   0x1337,
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).To(MatchError("StreamFrame: attempting to write empty frame without FIN"))
		})
	})

	Context("length", func() {
		It("has the right length for a frame without offset and data length", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Data:     []byte("foobar"),
			}
			Expect(f.MinLength(versionIETFFrames)).To(Equal(1 + utils.VarIntLen(0x1337)))
		})

		It("has the right length for a frame with offset", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Offset:   0x42,
				Data:     []byte("foobar"),
			}
			Expect(f.MinLength(versionIETFFrames)).To(Equal(1 + utils.VarIntLen(0x1337) + utils.VarIntLen(0x42)))
		})

		It("has the right length for a frame with data length", func() {
			f := &StreamFrame{
				StreamID:       0x1337,
				Offset:         0x1234567,
				DataLenPresent: true,
				Data:           []byte("foobar"),
			}
			Expect(f.MinLength(versionIETFFrames)).To(Equal(1 + utils.VarIntLen(0x1337) + utils.VarIntLen(0x1234567) + utils.VarIntLen(6)))
		})
	})
})
