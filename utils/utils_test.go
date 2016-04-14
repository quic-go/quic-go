package utils

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Utils", func() {
	Context("WriteUint64", func() {
		It("outputs 8 bytes", func() {
			b := &bytes.Buffer{}
			WriteUint64(b, uint64(1))
			Expect(b.Len()).To(Equal(8))
		})

		It("outputs a little endian", func() {
			num := uint64(0xFFEEDDCCBBAA9988)
			b := &bytes.Buffer{}
			WriteUint64(b, num)
			Expect(b.Bytes()).To(Equal([]byte{0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}))
		})
	})

	Context("ReadUint16", func() {
		It("reads a little endian", func() {
			b := []byte{0x13, 0xEF}
			val, err := ReadUint16(bytes.NewReader(b))
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint16(0xEF13)))
		})

		It("throws an error if less than 2 bytes are passed", func() {
			b := []byte{0x13}
			_, err := ReadUint16(bytes.NewReader(b))
			Expect(err).To(HaveOccurred())
		})
	})

	Context("ReadUint32", func() {
		It("reads a little endian", func() {
			b := []byte{0x12, 0x35, 0xAB, 0xFF}
			val, err := ReadUint32(bytes.NewReader(b))
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint32(0xFFAB3512)))
		})

		It("throws an error if less than 4 bytes are passed", func() {
			b := []byte{0x13, 0x34, 0xEA}
			_, err := ReadUint32(bytes.NewReader(b))
			Expect(err).To(HaveOccurred())
		})
	})

	Context("ReadUint32BigEndian", func() {
		It("reads a big endian", func() {
			b := []byte{0x12, 0x35, 0xAB, 0xFF}
			val, err := ReadUint32BigEndian(bytes.NewReader(b))
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint32(0x1235ABFF)))
		})

		It("throws an error if less than 4 bytes are passed", func() {
			b := []byte{0x13, 0x34, 0xEA}
			_, err := ReadUint32(bytes.NewReader(b))
			Expect(err).To(HaveOccurred())
		})
	})

	Context("WriteUint16", func() {
		It("outputs 2 bytes", func() {
			b := &bytes.Buffer{}
			WriteUint16(b, uint16(1))
			Expect(b.Len()).To(Equal(2))
		})

		It("outputs a little endian", func() {
			num := uint16(0xFF11)
			b := &bytes.Buffer{}
			WriteUint16(b, num)
			Expect(b.Bytes()).To(Equal([]byte{0x11, 0xFF}))
		})
	})

	Context("WriteUint32", func() {
		It("outputs 4 bytes", func() {
			b := &bytes.Buffer{}
			WriteUint32(b, uint32(1))
			Expect(b.Len()).To(Equal(4))
		})

		It("outputs a little endian", func() {
			num := uint32(0xEFAC3512)
			b := &bytes.Buffer{}
			WriteUint32(b, num)
			Expect(b.Bytes()).To(Equal([]byte{0x12, 0x35, 0xAC, 0xEF}))
		})
	})

	Context("WriteUint32BigEndian", func() {
		It("outputs 4 bytes", func() {
			b := &bytes.Buffer{}
			WriteUint32BigEndian(b, uint32(1))
			Expect(b.Len()).To(Equal(4))
		})

		It("outputs a big endian", func() {
			num := uint32(0xEFAC3512)
			b := &bytes.Buffer{}
			WriteUint32BigEndian(b, num)
			Expect(b.Bytes()).To(Equal([]byte{0xEF, 0xAC, 0x35, 0x12}))
		})
	})
})
