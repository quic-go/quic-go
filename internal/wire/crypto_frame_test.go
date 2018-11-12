package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CRYPTO frame", func() {
	Context("when parsing", func() {
		It("parses", func() {
			data := []byte{0x6}
			data = append(data, encodeVarInt(0xdecafbad)...) // offset
			data = append(data, encodeVarInt(6)...)          // length
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			frame, err := parseCryptoFrame(r, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Offset).To(Equal(protocol.ByteCount(0xdecafbad)))
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(r.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x6}
			data = append(data, encodeVarInt(0xdecafbad)...) // offset
			data = append(data, encodeVarInt(6)...)          // data length
			data = append(data, []byte("foobar")...)
			_, err := parseCryptoFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseCryptoFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		It("writes a frame", func() {
			f := &CryptoFrame{
				Offset: 0x123456,
				Data:   []byte("foobar"),
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x6}
			expected = append(expected, encodeVarInt(0x123456)...) // offset
			expected = append(expected, encodeVarInt(6)...)        // length
			expected = append(expected, []byte("foobar")...)
			Expect(b.Bytes()).To(Equal(expected))
		})
	})

	Context("max data length", func() {
		const maxSize = 3000

		It("always returns a data length such that the resulting frame has the right size", func() {
			data := make([]byte, maxSize)
			f := &CryptoFrame{
				Offset: 0xdeadbeef,
			}
			b := &bytes.Buffer{}
			var frameOneByteTooSmallCounter int
			for i := 1; i < maxSize; i++ {
				b.Reset()
				f.Data = nil
				maxDataLen := f.MaxDataLen(protocol.ByteCount(i))
				if maxDataLen == 0 { // 0 means that no valid CRYTPO frame can be written
					// check that writing a minimal size CRYPTO frame (i.e. with 1 byte data) is actually larger than the desired size
					f.Data = []byte{0}
					err := f.Write(b, versionIETFFrames)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Len()).To(BeNumerically(">", i))
					continue
				}
				f.Data = data[:int(maxDataLen)]
				err := f.Write(b, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				// There's *one* pathological case, where a data length of x can be encoded into 1 byte
				// but a data lengths of x+1 needs 2 bytes
				// In that case, it's impossible to create a STREAM frame of the desired size
				if b.Len() == i-1 {
					frameOneByteTooSmallCounter++
					continue
				}
				Expect(b.Len()).To(Equal(i))
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
			Expect(f.Length(versionIETFFrames)).To(Equal(1 + utils.VarIntLen(0x1337) + utils.VarIntLen(6) + 6))
		})
	})
})
