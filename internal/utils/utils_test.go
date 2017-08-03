package utils

import (
	"bytes"
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Utils", func() {
	Context("ReadUint16", func() {
		It("reads a little endian", func() {
			b := []byte{0x13, 0xEF}
			val, err := ReadUint16(bytes.NewReader(b))
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint16(0xEF13)))
		})

		It("throws an error if less than 2 bytes are passed", func() {
			b := []byte{0x13, 0xEF}
			for i := 0; i < len(b); i++ {
				_, err := ReadUint16(bytes.NewReader(b[:i]))
				Expect(err).To(MatchError(io.EOF))
			}
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
			b := []byte{0x12, 0x35, 0xAB, 0xFF}
			for i := 0; i < len(b); i++ {
				_, err := ReadUint32(bytes.NewReader(b[:i]))
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("ReadUint64", func() {
		It("reads a little endian", func() {
			b := []byte{0x12, 0x35, 0xAB, 0xFF, 0xEF, 0xBE, 0xAD, 0xDE}
			val, err := ReadUint64(bytes.NewReader(b))
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint64(0xDEADBEEFFFAB3512)))
		})

		It("throws an error if less than 8 bytes are passed", func() {
			b := []byte{0x12, 0x35, 0xAB, 0xFF, 0xEF, 0xBE, 0xAD, 0xDE}
			for i := 0; i < len(b); i++ {
				_, err := ReadUint64(bytes.NewReader(b[:i]))
				Expect(err).To(MatchError(io.EOF))
			}
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

	Context("WriteUint24", func() {
		It("outputs 3 bytes", func() {
			b := &bytes.Buffer{}
			WriteUint24(b, uint32(1))
			Expect(b.Len()).To(Equal(3))
		})

		It("outputs a little endian", func() {
			num := uint32(0xEFAC3512)
			b := &bytes.Buffer{}
			WriteUint24(b, num)
			Expect(b.Bytes()).To(Equal([]byte{0x12, 0x35, 0xAC}))
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

	Context("WriteUint40", func() {
		It("outputs 5 bytes", func() {
			b := &bytes.Buffer{}
			WriteUint40(b, uint64(1))
			Expect(b.Len()).To(Equal(5))
		})

		It("outputs a little endian", func() {
			num := uint64(0xDEADBEEFCAFE)
			b := &bytes.Buffer{}
			WriteUint40(b, num)
			Expect(b.Bytes()).To(Equal([]byte{0xFE, 0xCA, 0xEF, 0xBE, 0xAD}))
		})
	})

	Context("WriteUint48", func() {
		It("outputs 6 bytes", func() {
			b := &bytes.Buffer{}
			WriteUint48(b, uint64(1))
			Expect(b.Len()).To(Equal(6))
		})

		It("outputs a little endian", func() {
			num := uint64(0xDEADBEEFCAFE)
			b := &bytes.Buffer{}
			WriteUint48(b, num)
			Expect(b.Bytes()).To(Equal([]byte{0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE}))
		})

		It("doesn't care about the two higher order bytes", func() {
			num := uint64(0x1337DEADBEEFCAFE)
			b := &bytes.Buffer{}
			WriteUint48(b, num)
			Expect(b.Len()).To(Equal(6))
			Expect(b.Bytes()).To(Equal([]byte{0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE}))
		})
	})

	Context("WriteUint56", func() {
		It("outputs 7 bytes", func() {
			b := &bytes.Buffer{}
			WriteUint56(b, uint64(1))
			Expect(b.Len()).To(Equal(7))
		})

		It("outputs a little endian", func() {
			num := uint64(0xFFEEDDCCBBAA9988)
			b := &bytes.Buffer{}
			WriteUint56(b, num)
			Expect(b.Bytes()).To(Equal([]byte{0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}))
		})
	})

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
