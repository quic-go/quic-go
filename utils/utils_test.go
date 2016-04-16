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

	Context("Max", func() {
		It("returns the maximum", func() {
			Expect(Max(5, 7)).To(Equal(7))
		})
	})

	Context("Min", func() {
		It("returns the minimum", func() {
			Expect(Min(5, 7)).To(Equal(5))
		})
	})

	Context("ReadUintN", func() {
		It("reads n bytes", func() {
			m := map[uint8]uint64{
				0: 0x0, 1: 0x01, 2: 0x0201, 3: 0x030201, 4: 0x04030201, 5: 0x0504030201,
				6: 0x060504030201, 7: 0x07060504030201, 8: 0x0807060504030201,
			}
			for n, expected := range m {
				b := bytes.NewReader([]byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8})
				i, err := ReadUintN(b, n)
				Expect(err).ToNot(HaveOccurred())
				Expect(i).To(Equal(expected))
			}
		})

		It("errors", func() {
			b := bytes.NewReader([]byte{0x1, 0x2})
			_, err := ReadUintN(b, 3)
			Expect(err).To(HaveOccurred())
		})
	})
})
