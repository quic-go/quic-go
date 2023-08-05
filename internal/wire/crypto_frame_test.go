package wire

import (
	"bytes"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CRYPTO frame", func() {
	Context("when parsing", func() {
		It("parses", func() {
			data := encodeVarInt(0xdecafbad)        // offset
			data = append(data, encodeVarInt(6)...) // length
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			frame, err := parseCryptoFrame(r, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Offset).To(Equal(protocol.ByteCount(0xdecafbad)))
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(r.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := encodeVarInt(0xdecafbad)        // offset
			data = append(data, encodeVarInt(6)...) // data length
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			_, err := parseCryptoFrame(r, protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseCryptoFrame(bytes.NewReader(data[:i]), protocol.Version1)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("when writing", func() {
		It("writes a frame", func() {
			f := &CryptoFrame{
				Offset: 0x123456,
				Data:   []byte("foobar"),
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{cryptoFrameType}
			expected = append(expected, encodeVarInt(0x123456)...) // offset
			expected = append(expected, encodeVarInt(6)...)        // length
			expected = append(expected, []byte("foobar")...)
			Expect(b).To(Equal(expected))
		})
	})

	Context("max data length", func() {
		const maxSize = 3000

		It("always returns a data length such that the resulting frame has the right size", func() {
			data := make([]byte, maxSize)
			f := &CryptoFrame{
				Offset: 0xdeadbeef,
			}
			var frameOneByteTooSmallCounter int
			for i := 1; i < maxSize; i++ {
				f.Data = nil
				maxDataLen := f.MaxDataLen(protocol.ByteCount(i))
				if maxDataLen == 0 { // 0 means that no valid CRYTPO frame can be written
					// check that writing a minimal size CRYPTO frame (i.e. with 1 byte data) is actually larger than the desired size
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

	Context("length", func() {
		It("has the right length for a frame without offset and data length", func() {
			f := &CryptoFrame{
				Offset: 0x1337,
				Data:   []byte("foobar"),
			}
			Expect(f.Length(protocol.Version1)).To(Equal(1 + quicvarint.Len(0x1337) + quicvarint.Len(6) + 6))
		})
	})

	Context("splitting", func() {
		It("splits a frame", func() {
			f := &CryptoFrame{
				Offset: 0x1337,
				Data:   []byte("foobar"),
			}
			hdrLen := f.Length(protocol.Version1) - 6
			new, needsSplit := f.MaybeSplitOffFrame(hdrLen+3, protocol.Version1)
			Expect(needsSplit).To(BeTrue())
			Expect(new.Data).To(Equal([]byte("foo")))
			Expect(new.Offset).To(Equal(protocol.ByteCount(0x1337)))
			Expect(f.Data).To(Equal([]byte("bar")))
			Expect(f.Offset).To(Equal(protocol.ByteCount(0x1337 + 3)))
		})

		It("doesn't split if there's enough space in the frame", func() {
			f := &CryptoFrame{
				Offset: 0x1337,
				Data:   []byte("foobar"),
			}
			f, needsSplit := f.MaybeSplitOffFrame(f.Length(protocol.Version1), protocol.Version1)
			Expect(needsSplit).To(BeFalse())
			Expect(f).To(BeNil())
		})

		It("doesn't split if the size is too small", func() {
			f := &CryptoFrame{
				Offset: 0x1337,
				Data:   []byte("foobar"),
			}
			length := f.Length(protocol.Version1) - 6
			for i := protocol.ByteCount(0); i <= length; i++ {
				f, needsSplit := f.MaybeSplitOffFrame(i, protocol.Version1)
				Expect(needsSplit).To(BeTrue())
				Expect(f).To(BeNil())
			}
			f, needsSplit := f.MaybeSplitOffFrame(length+1, protocol.Version1)
			Expect(needsSplit).To(BeTrue())
			Expect(f).ToNot(BeNil())
		})
	})
})
