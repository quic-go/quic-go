package utils

import (
	"bytes"
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("RingBuffer", func() {
	Context("constructor", func() {
		It("creates a byte slice of the correct size", func() {
			rb := NewRingBuffer(1337).(*ringBuffer)
			Expect(len(rb.data)).To(Equal(1337))
			Expect(cap(rb.data)).To(Equal(1337))
		})

		It("returns the right size", func() {
			rb := NewRingBuffer(1337)
			Expect(rb.Len()).To(Equal(uint64(1337)))
		})

		It("sets the correct writeCapacity", func() {
			rb := NewRingBuffer(1337).(*ringBuffer)
			Expect(rb.writeCapacity).To(Equal(uint64(1337)))
		})
	})

	Context("usage", func() {
		var rb *ringBuffer
		var capacity uint64

		BeforeEach(func() {
			capacity = 32
			rb = NewRingBuffer(capacity).(*ringBuffer)
		})

		Context("Write", func() {
			It("writes small sample data", func() {
				err := rb.Write([]byte{0x11, 0x22}, 0)
				Expect(err).ToNot(HaveOccurred())
				err = rb.Write([]byte{0x33, 0x44}, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(rb.data[0:4]).To(Equal([]byte{0x11, 0x22, 0x33, 0x44}))
			})

			It("writes at an offset", func() {
				err := rb.Write([]byte{0x11, 0x22}, 2)
				Expect(err).ToNot(HaveOccurred())
				Expect(rb.data[2:4]).To(Equal([]byte{0x11, 0x22}))
			})

			It("handles multiple writes with an offset", func() {
				err := rb.Write([]byte{0x11, 0x22}, 2)
				Expect(err).ToNot(HaveOccurred())
				err = rb.Write([]byte{0x33, 0x44}, 1)
				Expect(err).ToNot(HaveOccurred())
				Expect(rb.data[2:7]).To(Equal([]byte{0x11, 0x22, 0, 0x33, 0x44}))
			})

			It("doesn't write if it doesn't fit, when using an offset", func() {
				err := rb.Write([]byte{0x11, 0x22}, capacity-1)
				Expect(err).To(MatchError(io.EOF))
			})

			It("wraps data around at the end of the slice", func() {
				rb.writePosition = capacity - 2
				err := rb.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD}, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(rb.data[capacity-2 : capacity]).To(Equal([]byte{0xDE, 0xCA}))
				Expect(rb.data[0:2]).To(Equal([]byte{0xFB, 0xAD}))
			})

			It("does not write if limited by the clearPosition", func() {
				rb.writePosition = 19
				rb.writeCapacity = 1
				err := rb.Write([]byte{0x11, 0x22}, 0)
				Expect(err).To(MatchError(io.EOF))
			})

			It("writes the maximum amount of data possible", func() {
				rb.writePosition = 19
				rb.writeCapacity = 2
				err := rb.Write([]byte{0x11, 0x22}, 0)
				Expect(err).ToNot(HaveOccurred())
			})

			It("returns an error when not enough write capacity is left", func() {
				rb.writePosition = 19
				rb.writeCapacity = 0
				err := rb.Write([]byte{0x11}, 0)
				Expect(err).To(MatchError(io.EOF))
			})

			It("does not write more data than possible", func() {
				err := rb.Write(bytes.Repeat([]byte{'a'}, int(capacity)), 0)
				Expect(err).ToNot(HaveOccurred())
				err = rb.Write([]byte{0x11}, 0)
				Expect(err).To(MatchError(io.EOF))
			})
		})

		Context("Read", func() {
			It("reads everything requested, when possible", func() {
				rb.writePosition = 20
				data, n, err := rb.Read(10)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(uint64(10)))
				Expect(data).To(HaveLen(10))
			})

			It("does repeated reads correctly", func() {
				err := rb.Write([]byte{0x11, 0x22, 0x33, 0x44}, 0)
				Expect(err).ToNot(HaveOccurred())
				data, n, err := rb.Read(2)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(uint64(2)))
				Expect(data).To(Equal([]byte{0x11, 0x22}))
				data, n, err = rb.Read(2)
				Expect(err).To(MatchError(io.EOF))
				Expect(n).To(Equal(uint64(2)))
				Expect(data).To(Equal([]byte{0x33, 0x44}))
			})

			It("reads everything and returns an io.EOF", func() {
				rb.writePosition = 20
				data, n, err := rb.Read(20)
				Expect(err).To(MatchError(io.EOF))
				Expect(n).To(Equal(uint64(20)))
				Expect(data).To(HaveLen(20))
			})

			It("does not read anything when readPosition = writePosition", func() {
				rb.writePosition = 13
				rb.readPosition = 13
				data, n, err := rb.Read(1)
				Expect(err).To(MatchError(io.EOF))
				Expect(n).To(Equal(uint64(0)))
				Expect(data).To(HaveLen(0))
			})

			It("returns a shorter slice when reading from the end", func() {
				rb.readPosition = capacity - 2
				data, n, err := rb.Read(4)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(uint64(2)))
				Expect(data).To(HaveLen(2))
			})
		})

		Context("Clear", func() {
			It("sets the clear position", func() {
				rb.writeCapacity = 5
				err := rb.Clear(10)
				Expect(err).ToNot(HaveOccurred())
				Expect(rb.writeCapacity).To(Equal(uint64(15)))
			})

			It("does repeated clears", func() {
				rb.writeCapacity = 5
				err := rb.Clear(6)
				Expect(err).ToNot(HaveOccurred())
				Expect(rb.writeCapacity).To(Equal(uint64(11)))
				err = rb.Clear(6)
				Expect(err).ToNot(HaveOccurred())
				Expect(rb.writeCapacity).To(Equal(uint64(17)))
			})

			It("doesn't overflow the writeCapacity", func() {
				rb.writeCapacity = capacity - 2
				err := rb.Clear(10)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("full cycle", func() {
			It("does a full cycle", func() {
				for i := uint64(0); i < capacity; i++ {
					err := rb.Write([]byte{byte(i)}, 0)
					Expect(err).ToNot(HaveOccurred())
				}
				err := rb.Write([]byte{'a'}, 0)
				Expect(err).To(MatchError(io.EOF))
			})
		})
	})
})
