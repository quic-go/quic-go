package quicvarint

import (
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Varint encoding / decoding", func() {
	Context("limits", func() {
		Specify("Min == 0", func() {
			Expect(Min).To(Equal(0))
		})

		Specify("Max == 2^62-1", func() {
			Expect(uint64(Max)).To(Equal(uint64(1<<62 - 1)))
		})
	})

	Context("decoding", func() {
		It("reads a 1 byte number", func() {
			b := bytes.NewReader([]byte{0b00011001})
			val, err := Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint64(25)))
			Expect(b.Len()).To(BeZero())
		})

		It("reads a number that is encoded too long", func() {
			b := bytes.NewReader([]byte{0b01000000, 0x25})
			val, err := Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint64(37)))
			Expect(b.Len()).To(BeZero())
		})

		It("reads a 2 byte number", func() {
			b := bytes.NewReader([]byte{0b01111011, 0xbd})
			val, err := Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint64(15293)))
			Expect(b.Len()).To(BeZero())
		})

		It("reads a 4 byte number", func() {
			b := bytes.NewReader([]byte{0b10011101, 0x7f, 0x3e, 0x7d})
			val, err := Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint64(494878333)))
			Expect(b.Len()).To(BeZero())
		})

		It("reads an 8 byte number", func() {
			b := bytes.NewReader([]byte{0b11000010, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c})
			val, err := Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint64(151288809941952652)))
			Expect(b.Len()).To(BeZero())
		})
	})

	Context("encoding", func() {
		Context("with minimal length", func() {
			It("writes a 1 byte number", func() {
				Expect(Append(nil, 37)).To(Equal([]byte{0x25}))
			})

			It("writes the maximum 1 byte number in 1 byte", func() {
				Expect(Append(nil, maxVarInt1)).To(Equal([]byte{0b00111111}))
			})

			It("writes the minimum 2 byte number in 2 bytes", func() {
				Expect(Append(nil, maxVarInt1+1)).To(Equal([]byte{0x40, maxVarInt1 + 1}))
			})

			It("writes a 2 byte number", func() {
				Expect(Append(nil, 15293)).To(Equal([]byte{0b01000000 ^ 0x3b, 0xbd}))
			})

			It("writes the maximum 2 byte number in 2 bytes", func() {
				Expect(Append(nil, maxVarInt2)).To(Equal([]byte{0b01111111, 0xff}))
			})

			It("writes the minimum 4 byte number in 4 bytes", func() {
				b := Append(nil, maxVarInt2+1)
				Expect(b).To(HaveLen(4))
				num, err := Read(bytes.NewReader(b))
				Expect(err).ToNot(HaveOccurred())
				Expect(num).To(Equal(uint64(maxVarInt2 + 1)))
			})

			It("writes a 4 byte number", func() {
				Expect(Append(nil, 494878333)).To(Equal([]byte{0b10000000 ^ 0x1d, 0x7f, 0x3e, 0x7d}))
			})

			It("writes the maximum 4 byte number in 4 bytes", func() {
				Expect(Append(nil, maxVarInt4)).To(Equal([]byte{0b10111111, 0xff, 0xff, 0xff}))
			})

			It("writes the minimum 8 byte number in 8 bytes", func() {
				b := Append(nil, maxVarInt4+1)
				Expect(b).To(HaveLen(8))
				num, err := Read(bytes.NewReader(b))
				Expect(err).ToNot(HaveOccurred())
				Expect(num).To(Equal(uint64(maxVarInt4 + 1)))
			})

			It("writes an 8 byte number", func() {
				Expect(Append(nil, 151288809941952652)).To(Equal([]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}))
			})

			It("writes the maximum 8 byte number in 8 bytes", func() {
				Expect(Append(nil, maxVarInt8)).To(Equal([]byte{0xff /* 11111111 */, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}))
			})

			It("panics when given a too large number (> 62 bit)", func() {
				Expect(func() { Append(nil, maxVarInt8+1) }).Should(Panic())
			})
		})

		Context("with fixed length", func() {
			It("panics when given an invalid length", func() {
				Expect(func() { AppendWithLen(nil, 25, 3) }).Should(Panic())
			})

			It("panics when given a too short length", func() {
				Expect(func() { AppendWithLen(nil, maxVarInt1+1, 1) }).Should(Panic())
				Expect(func() { AppendWithLen(nil, maxVarInt2+1, 2) }).Should(Panic())
				Expect(func() { AppendWithLen(nil, maxVarInt4+1, 4) }).Should(Panic())
			})

			It("writes a 1-byte number in minimal encoding", func() {
				Expect(AppendWithLen(nil, 37, 1)).To(Equal([]byte{0x25}))
			})

			It("writes a 1-byte number in 2 bytes", func() {
				b := AppendWithLen(nil, 37, 2)
				Expect(b).To(Equal([]byte{0b01000000, 0x25}))
				Expect(Read(bytes.NewReader(b))).To(BeEquivalentTo(37))
			})

			It("writes a 1-byte number in 4 bytes", func() {
				b := AppendWithLen(nil, 37, 4)
				Expect(b).To(Equal([]byte{0b10000000, 0, 0, 0x25}))
				Expect(Read(bytes.NewReader(b))).To(BeEquivalentTo(37))
			})

			It("writes a 1-byte number in 8 bytes", func() {
				b := AppendWithLen(nil, 37, 8)
				Expect(b).To(Equal([]byte{0b11000000, 0, 0, 0, 0, 0, 0, 0x25}))
				Expect(Read(bytes.NewReader(b))).To(BeEquivalentTo(37))
			})

			It("writes a 2-byte number in 4 bytes", func() {
				b := AppendWithLen(nil, 15293, 4)
				Expect(b).To(Equal([]byte{0b10000000, 0, 0x3b, 0xbd}))
				Expect(Read(bytes.NewReader(b))).To(BeEquivalentTo(15293))
			})

			It("write a 4-byte number in 8 bytes", func() {
				b := AppendWithLen(nil, 494878333, 8)
				Expect(b).To(Equal([]byte{0b11000000, 0, 0, 0, 0x1d, 0x7f, 0x3e, 0x7d}))
				Expect(Read(bytes.NewReader(b))).To(BeEquivalentTo(494878333))
			})
		})
	})

	Context("determining the length needed for encoding", func() {
		It("for numbers that need 1 byte", func() {
			Expect(Len(0)).To(BeEquivalentTo(1))
			Expect(Len(maxVarInt1)).To(BeEquivalentTo(1))
		})

		It("for numbers that need 2 bytes", func() {
			Expect(Len(maxVarInt1 + 1)).To(BeEquivalentTo(2))
			Expect(Len(maxVarInt2)).To(BeEquivalentTo(2))
		})

		It("for numbers that need 4 bytes", func() {
			Expect(Len(maxVarInt2 + 1)).To(BeEquivalentTo(4))
			Expect(Len(maxVarInt4)).To(BeEquivalentTo(4))
		})

		It("for numbers that need 8 bytes", func() {
			Expect(Len(maxVarInt4 + 1)).To(BeEquivalentTo(8))
			Expect(Len(maxVarInt8)).To(BeEquivalentTo(8))
		})

		It("panics when given a too large number (> 62 bit)", func() {
			Expect(func() { Len(maxVarInt8 + 1) }).Should(Panic())
		})
	})
})
