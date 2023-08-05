package wire

import (
	"bytes"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("STREAM frame", func() {
	Context("when parsing", func() {
		It("parses a frame with OFF bit", func() {
			data := encodeVarInt(0x12345)                    // stream ID
			data = append(data, encodeVarInt(0xdecafbad)...) // offset
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			frame, err := parseStreamFrame(r, 0x8^0x4, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0x12345)))
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(frame.Fin).To(BeFalse())
			Expect(frame.Offset).To(Equal(protocol.ByteCount(0xdecafbad)))
			Expect(r.Len()).To(BeZero())
		})

		It("respects the LEN when parsing the frame", func() {
			data := encodeVarInt(0x12345)           // stream ID
			data = append(data, encodeVarInt(4)...) // data length
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			frame, err := parseStreamFrame(r, 0x8^0x2, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0x12345)))
			Expect(frame.Data).To(Equal([]byte("foob")))
			Expect(frame.Fin).To(BeFalse())
			Expect(frame.Offset).To(BeZero())
			Expect(r.Len()).To(Equal(2))
		})

		It("parses a frame with FIN bit", func() {
			data := encodeVarInt(9) // stream ID
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			frame, err := parseStreamFrame(r, 0x8^0x1, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(9)))
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(frame.Fin).To(BeTrue())
			Expect(frame.Offset).To(BeZero())
			Expect(r.Len()).To(BeZero())
		})

		It("allows empty frames", func() {
			data := encodeVarInt(0x1337)                  // stream ID
			data = append(data, encodeVarInt(0x12345)...) // offset
			r := bytes.NewReader(data)
			f, err := parseStreamFrame(r, 0x8^0x4, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.StreamID).To(Equal(protocol.StreamID(0x1337)))
			Expect(f.Offset).To(Equal(protocol.ByteCount(0x12345)))
			Expect(f.Data).To(BeEmpty())
			Expect(f.Fin).To(BeFalse())
		})

		It("rejects frames that overflow the maximum offset", func() {
			data := encodeVarInt(0x12345)                                         // stream ID
			data = append(data, encodeVarInt(uint64(protocol.MaxByteCount-5))...) // offset
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			_, err := parseStreamFrame(r, 0x8^0x4, protocol.Version1)
			Expect(err).To(MatchError("stream data overflows maximum offset"))
		})

		It("rejects frames that claim to be longer than the packet size", func() {
			data := encodeVarInt(0x12345)                                                // stream ID
			data = append(data, encodeVarInt(uint64(protocol.MaxPacketBufferSize)+1)...) // data length
			data = append(data, make([]byte, protocol.MaxPacketBufferSize+1)...)
			r := bytes.NewReader(data)
			_, err := parseStreamFrame(r, 0x8^0x2, protocol.Version1)
			Expect(err).To(Equal(io.EOF))
		})

		It("errors on EOFs", func() {
			typ := uint64(0x8 ^ 0x4 ^ 0x2)
			data := encodeVarInt(0x12345)                    // stream ID
			data = append(data, encodeVarInt(0xdecafbad)...) // offset
			data = append(data, encodeVarInt(6)...)          // data length
			data = append(data, []byte("foobar")...)
			_, err := parseStreamFrame(bytes.NewReader(data), typ, protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err = parseStreamFrame(bytes.NewReader(data[:i]), typ, protocol.Version1)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("using the buffer", func() {
		It("uses the buffer for long STREAM frames", func() {
			data := encodeVarInt(0x12345) // stream ID
			data = append(data, bytes.Repeat([]byte{'f'}, protocol.MinStreamFrameBufferSize)...)
			r := bytes.NewReader(data)
			frame, err := parseStreamFrame(r, 0x8, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0x12345)))
			Expect(frame.Data).To(Equal(bytes.Repeat([]byte{'f'}, protocol.MinStreamFrameBufferSize)))
			Expect(frame.DataLen()).To(BeEquivalentTo(protocol.MinStreamFrameBufferSize))
			Expect(frame.Fin).To(BeFalse())
			Expect(frame.fromPool).To(BeTrue())
			Expect(r.Len()).To(BeZero())
			Expect(frame.PutBack).ToNot(Panic())
		})

		It("doesn't use the buffer for short STREAM frames", func() {
			data := encodeVarInt(0x12345) // stream ID
			data = append(data, bytes.Repeat([]byte{'f'}, protocol.MinStreamFrameBufferSize-1)...)
			r := bytes.NewReader(data)
			frame, err := parseStreamFrame(r, 0x8, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0x12345)))
			Expect(frame.Data).To(Equal(bytes.Repeat([]byte{'f'}, protocol.MinStreamFrameBufferSize-1)))
			Expect(frame.DataLen()).To(BeEquivalentTo(protocol.MinStreamFrameBufferSize - 1))
			Expect(frame.Fin).To(BeFalse())
			Expect(frame.fromPool).To(BeFalse())
			Expect(r.Len()).To(BeZero())
			Expect(frame.PutBack).ToNot(Panic())
		})
	})

	Context("when writing", func() {
		It("writes a frame without offset", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Data:     []byte("foobar"),
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x8}
			expected = append(expected, encodeVarInt(0x1337)...) // stream ID
			expected = append(expected, []byte("foobar")...)
			Expect(b).To(Equal(expected))
		})

		It("writes a frame with offset", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Offset:   0x123456,
				Data:     []byte("foobar"),
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x8 ^ 0x4}
			expected = append(expected, encodeVarInt(0x1337)...)   // stream ID
			expected = append(expected, encodeVarInt(0x123456)...) // offset
			expected = append(expected, []byte("foobar")...)
			Expect(b).To(Equal(expected))
		})

		It("writes a frame with FIN bit", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Offset:   0x123456,
				Fin:      true,
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x8 ^ 0x4 ^ 0x1}
			expected = append(expected, encodeVarInt(0x1337)...)   // stream ID
			expected = append(expected, encodeVarInt(0x123456)...) // offset
			Expect(b).To(Equal(expected))
		})

		It("writes a frame with data length", func() {
			f := &StreamFrame{
				StreamID:       0x1337,
				Data:           []byte("foobar"),
				DataLenPresent: true,
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x8 ^ 0x2}
			expected = append(expected, encodeVarInt(0x1337)...) // stream ID
			expected = append(expected, encodeVarInt(6)...)      // data length
			expected = append(expected, []byte("foobar")...)
			Expect(b).To(Equal(expected))
		})

		It("writes a frame with data length and offset", func() {
			f := &StreamFrame{
				StreamID:       0x1337,
				Data:           []byte("foobar"),
				DataLenPresent: true,
				Offset:         0x123456,
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x8 ^ 0x4 ^ 0x2}
			expected = append(expected, encodeVarInt(0x1337)...)   // stream ID
			expected = append(expected, encodeVarInt(0x123456)...) // offset
			expected = append(expected, encodeVarInt(6)...)        // data length
			expected = append(expected, []byte("foobar")...)
			Expect(b).To(Equal(expected))
		})

		It("refuses to write an empty frame without FIN", func() {
			f := &StreamFrame{
				StreamID: 0x42,
				Offset:   0x1337,
			}
			_, err := f.Append(nil, protocol.Version1)
			Expect(err).To(MatchError("StreamFrame: attempting to write empty frame without FIN"))
		})
	})

	Context("length", func() {
		It("has the right length for a frame without offset and data length", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Data:     []byte("foobar"),
			}
			Expect(f.Length(protocol.Version1)).To(Equal(1 + quicvarint.Len(0x1337) + 6))
		})

		It("has the right length for a frame with offset", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Offset:   0x42,
				Data:     []byte("foobar"),
			}
			Expect(f.Length(protocol.Version1)).To(Equal(1 + quicvarint.Len(0x1337) + quicvarint.Len(0x42) + 6))
		})

		It("has the right length for a frame with data length", func() {
			f := &StreamFrame{
				StreamID:       0x1337,
				Offset:         0x1234567,
				DataLenPresent: true,
				Data:           []byte("foobar"),
			}
			Expect(f.Length(protocol.Version1)).To(Equal(1 + quicvarint.Len(0x1337) + quicvarint.Len(0x1234567) + quicvarint.Len(6) + 6))
		})
	})

	Context("max data length", func() {
		const maxSize = 3000

		It("always returns a data length such that the resulting frame has the right size, if data length is not present", func() {
			data := make([]byte, maxSize)
			f := &StreamFrame{
				StreamID: 0x1337,
				Offset:   0xdeadbeef,
			}
			for i := 1; i < 3000; i++ {
				f.Data = nil
				maxDataLen := f.MaxDataLen(protocol.ByteCount(i), protocol.Version1)
				if maxDataLen == 0 { // 0 means that no valid STREAM frame can be written
					// check that writing a minimal size STREAM frame (i.e. with 1 byte data) is actually larger than the desired size
					f.Data = []byte{0}
					b, err := f.Append(nil, protocol.Version1)
					Expect(err).ToNot(HaveOccurred())
					Expect(len(b)).To(BeNumerically(">", i))
					continue
				}
				f.Data = data[:int(maxDataLen)]
				b, err := f.Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(b)).To(Equal(i))
			}
		})

		It("always returns a data length such that the resulting frame has the right size, if data length is present", func() {
			data := make([]byte, maxSize)
			f := &StreamFrame{
				StreamID:       0x1337,
				Offset:         0xdeadbeef,
				DataLenPresent: true,
			}
			var frameOneByteTooSmallCounter int
			for i := 1; i < 3000; i++ {
				f.Data = nil
				maxDataLen := f.MaxDataLen(protocol.ByteCount(i), protocol.Version1)
				if maxDataLen == 0 { // 0 means that no valid STREAM frame can be written
					// check that writing a minimal size STREAM frame (i.e. with 1 byte data) is actually larger than the desired size
					f.Data = []byte{0}
					b, err := f.Append(nil, protocol.Version1)
					Expect(err).ToNot(HaveOccurred())
					Expect(len(b)).To(BeNumerically(">", i))
					continue
				}
				f.Data = data[:int(maxDataLen)]
				b, err := f.Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				// There's *one* pathological case, where a data length of x can be encoded into 1 byte
				// but a data lengths of x+1 needs 2 bytes
				// In that case, it's impossible to create a STREAM frame of the desired size
				if len(b) == i-1 {
					frameOneByteTooSmallCounter++
					continue
				}
				Expect(len(b)).To(Equal(i))
			}
			Expect(frameOneByteTooSmallCounter).To(Equal(1))
		})
	})

	Context("splitting", func() {
		It("doesn't split if the frame is short enough", func() {
			f := &StreamFrame{
				StreamID:       0x1337,
				DataLenPresent: true,
				Offset:         0xdeadbeef,
				Data:           make([]byte, 100),
			}
			frame, needsSplit := f.MaybeSplitOffFrame(f.Length(protocol.Version1), protocol.Version1)
			Expect(needsSplit).To(BeFalse())
			Expect(frame).To(BeNil())
			Expect(f.DataLen()).To(BeEquivalentTo(100))
			frame, needsSplit = f.MaybeSplitOffFrame(f.Length(protocol.Version1)-1, protocol.Version1)
			Expect(needsSplit).To(BeTrue())
			Expect(frame.DataLen()).To(BeEquivalentTo(99))
			f.PutBack()
		})

		It("keeps the data len", func() {
			f := &StreamFrame{
				StreamID:       0x1337,
				DataLenPresent: true,
				Data:           make([]byte, 100),
			}
			frame, needsSplit := f.MaybeSplitOffFrame(66, protocol.Version1)
			Expect(needsSplit).To(BeTrue())
			Expect(frame).ToNot(BeNil())
			Expect(f.DataLenPresent).To(BeTrue())
			Expect(frame.DataLenPresent).To(BeTrue())
		})

		It("adjusts the offset", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Offset:   0x100,
				Data:     []byte("foobar"),
			}
			frame, needsSplit := f.MaybeSplitOffFrame(f.Length(protocol.Version1)-3, protocol.Version1)
			Expect(needsSplit).To(BeTrue())
			Expect(frame).ToNot(BeNil())
			Expect(frame.Offset).To(Equal(protocol.ByteCount(0x100)))
			Expect(frame.Data).To(Equal([]byte("foo")))
			Expect(f.Offset).To(Equal(protocol.ByteCount(0x100 + 3)))
			Expect(f.Data).To(Equal([]byte("bar")))
		})

		It("preserves the FIN bit", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Fin:      true,
				Offset:   0xdeadbeef,
				Data:     make([]byte, 100),
			}
			frame, needsSplit := f.MaybeSplitOffFrame(50, protocol.Version1)
			Expect(needsSplit).To(BeTrue())
			Expect(frame).ToNot(BeNil())
			Expect(frame.Offset).To(BeNumerically("<", f.Offset))
			Expect(f.Fin).To(BeTrue())
			Expect(frame.Fin).To(BeFalse())
		})

		It("produces frames of the correct length, without data len", func() {
			const size = 1000
			f := &StreamFrame{
				StreamID: 0xdecafbad,
				Offset:   0x1234,
				Data:     []byte{0},
			}
			minFrameSize := f.Length(protocol.Version1)
			for i := protocol.ByteCount(0); i < minFrameSize; i++ {
				f, needsSplit := f.MaybeSplitOffFrame(i, protocol.Version1)
				Expect(needsSplit).To(BeTrue())
				Expect(f).To(BeNil())
			}
			for i := minFrameSize; i < size; i++ {
				f.fromPool = false
				f.Data = make([]byte, size)
				f, needsSplit := f.MaybeSplitOffFrame(i, protocol.Version1)
				Expect(needsSplit).To(BeTrue())
				Expect(f.Length(protocol.Version1)).To(Equal(i))
			}
		})

		It("produces frames of the correct length, with data len", func() {
			const size = 1000
			f := &StreamFrame{
				StreamID:       0xdecafbad,
				Offset:         0x1234,
				DataLenPresent: true,
				Data:           []byte{0},
			}
			minFrameSize := f.Length(protocol.Version1)
			for i := protocol.ByteCount(0); i < minFrameSize; i++ {
				f, needsSplit := f.MaybeSplitOffFrame(i, protocol.Version1)
				Expect(needsSplit).To(BeTrue())
				Expect(f).To(BeNil())
			}
			var frameOneByteTooSmallCounter int
			for i := minFrameSize; i < size; i++ {
				f.fromPool = false
				f.Data = make([]byte, size)
				newFrame, needsSplit := f.MaybeSplitOffFrame(i, protocol.Version1)
				Expect(needsSplit).To(BeTrue())
				// There's *one* pathological case, where a data length of x can be encoded into 1 byte
				// but a data lengths of x+1 needs 2 bytes
				// In that case, it's impossible to create a STREAM frame of the desired size
				if newFrame.Length(protocol.Version1) == i-1 {
					frameOneByteTooSmallCounter++
					continue
				}
				Expect(newFrame.Length(protocol.Version1)).To(Equal(i))
			}
			Expect(frameOneByteTooSmallCounter).To(Equal(1))
		})
	})
})
