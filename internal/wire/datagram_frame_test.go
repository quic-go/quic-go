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
		It("parses a frame containing a length", func() {
			data := encodeVarInt(0x6) // length
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			frame, err := parseDatagramFrame(r, 0x30^0x1, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(frame.DataLenPresent).To(BeTrue())
			Expect(r.Len()).To(BeZero())
		})

		It("parses a frame without length", func() {
			data := []byte("Lorem ipsum dolor sit amet")
			r := bytes.NewReader(data)
			frame, err := parseDatagramFrame(r, 0x30, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Data).To(Equal([]byte("Lorem ipsum dolor sit amet")))
			Expect(frame.DataLenPresent).To(BeFalse())
			Expect(r.Len()).To(BeZero())
		})

		It("errors when the length is longer than the rest of the frame", func() {
			data := encodeVarInt(0x6) // length
			data = append(data, []byte("fooba")...)
			r := bytes.NewReader(data)
			_, err := parseDatagramFrame(r, 0x30^0x1, protocol.Version1)
			Expect(err).To(MatchError(io.EOF))
		})

		It("errors on EOFs", func() {
			const typ = 0x30 ^ 0x1
			data := encodeVarInt(6) // length
			data = append(data, []byte("foobar")...)
			_, err := parseDatagramFrame(bytes.NewReader(data), typ, protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err = parseDatagramFrame(bytes.NewReader(data[0:i]), typ, protocol.Version1)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("when writing", func() {
		It("writes a frame with length", func() {
			f := &DatagramFrame{
				DataLenPresent: true,
				Data:           []byte("foobar"),
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x30 ^ 0x1}
			expected = append(expected, encodeVarInt(0x6)...)
			expected = append(expected, []byte("foobar")...)
			Expect(b).To(Equal(expected))
		})

		It("writes a frame without length", func() {
			f := &DatagramFrame{Data: []byte("Lorem ipsum")}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x30}
			expected = append(expected, []byte("Lorem ipsum")...)
			Expect(b).To(Equal(expected))
		})
	})

	Context("length", func() {
		It("has the right length for a frame with length", func() {
			f := &DatagramFrame{
				DataLenPresent: true,
				Data:           []byte("foobar"),
			}
			Expect(f.Length(protocol.Version1)).To(Equal(1 + quicvarint.Len(6) + 6))
		})

		It("has the right length for a frame without length", func() {
			f := &DatagramFrame{Data: []byte("foobar")}
			Expect(f.Length(protocol.Version1)).To(Equal(protocol.ByteCount(1 + 6)))
		})
	})

	Context("max data length", func() {
		const maxSize = 3000

		It("returns a data length such that the resulting frame has the right size, if data length is not present", func() {
			data := make([]byte, maxSize)
			f := &DatagramFrame{}
			b := &bytes.Buffer{}
			for i := 1; i < 3000; i++ {
				b.Reset()
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
				Expect(b).To(HaveLen(i))
			}
		})

		It("always returns a data length such that the resulting frame has the right size, if data length is present", func() {
			data := make([]byte, maxSize)
			f := &DatagramFrame{DataLenPresent: true}
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
				Expect(b).To(HaveLen(i))
			}
			Expect(frameOneByteTooSmallCounter).To(Equal(1))
		})
	})
})
