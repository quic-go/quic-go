package utils

import (
	"bytes"
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Big Endian encoding / decoding", func() {
	Context("ReadUint16", func() {
		It("reads a big endian", func() {
			b := []byte{0x13, 0xEF}
			val, err := BigEndian.ReadUint16(bytes.NewReader(b))
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint16(0x13EF)))
		})

		It("throws an error if less than 2 bytes are passed", func() {
			b := []byte{0x13, 0xEF}
			for i := 0; i < len(b); i++ {
				_, err := BigEndian.ReadUint16(bytes.NewReader(b[:i]))
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("ReadUint24", func() {
		It("reads a big endian", func() {
			b := []byte{0x13, 0xbe, 0xef}
			val, err := BigEndian.ReadUint24(bytes.NewReader(b))
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint32(0x13beef)))
		})

		It("throws an error if less than 3 bytes are passed", func() {
			b := []byte{0x13, 0xbe, 0xef}
			for i := 0; i < len(b); i++ {
				_, err := BigEndian.ReadUint24(bytes.NewReader(b[:i]))
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("ReadUint32", func() {
		It("reads a big endian", func() {
			b := []byte{0x12, 0x35, 0xAB, 0xFF}
			val, err := BigEndian.ReadUint32(bytes.NewReader(b))
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint32(0x1235ABFF)))
		})

		It("throws an error if less than 4 bytes are passed", func() {
			b := []byte{0x12, 0x35, 0xAB, 0xFF}
			for i := 0; i < len(b); i++ {
				_, err := BigEndian.ReadUint32(bytes.NewReader(b[:i]))
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("WriteUint16", func() {
		It("outputs 2 bytes", func() {
			b := &bytes.Buffer{}
			BigEndian.WriteUint16(b, uint16(1))
			Expect(b.Len()).To(Equal(2))
		})

		It("outputs a big endian", func() {
			num := uint16(0xFF11)
			b := &bytes.Buffer{}
			BigEndian.WriteUint16(b, num)
			Expect(b.Bytes()).To(Equal([]byte{0xFF, 0x11}))
		})
	})

	Context("WriteUint24", func() {
		It("outputs 3 bytes", func() {
			b := &bytes.Buffer{}
			BigEndian.WriteUint24(b, uint32(1))
			Expect(b.Len()).To(Equal(3))
		})

		It("outputs a big endian", func() {
			num := uint32(0xff11aa)
			b := &bytes.Buffer{}
			BigEndian.WriteUint24(b, num)
			Expect(b.Bytes()).To(Equal([]byte{0xff, 0x11, 0xaa}))
		})
	})

	Context("WriteUint32", func() {
		It("outputs 4 bytes", func() {
			b := &bytes.Buffer{}
			BigEndian.WriteUint32(b, uint32(1))
			Expect(b.Len()).To(Equal(4))
		})

		It("outputs a big endian", func() {
			num := uint32(0xEFAC3512)
			b := &bytes.Buffer{}
			BigEndian.WriteUint32(b, num)
			Expect(b.Bytes()).To(Equal([]byte{0xEF, 0xAC, 0x35, 0x12}))
		})
	})
})
