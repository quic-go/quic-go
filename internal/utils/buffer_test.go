package utils

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Buffer", func() {
	Context("writing single bytes", func() {
		It("writes", func() {
			buf := NewBuffer(make([]byte, 0, 10))
			buf.WriteByte('b')
			buf.WriteByte('a')
			buf.WriteByte('r')
			Expect(buf.String()).To(Equal("bar"))
		})

		It("appends to a given slice", func() {
			data := make([]byte, 3, 6)
			data[0] = byte('f')
			data[1] = byte('o')
			data[2] = byte('o')
			buf := NewBuffer(data)
			buf.WriteByte('b')
			buf.WriteByte('a')
			buf.WriteByte('r')
			Expect(buf.String()).To(Equal("foobar"))
		})

		It("panics when the underlying slice is too short", func() {
			buf := NewBuffer(make([]byte, 0, 1))
			buf.WriteByte('a')
			Expect(func() { buf.WriteByte('b') }).Should(Panic())
		})
	})

	Context("writing multiple bytes", func() {
		It("writes multiple bytes", func() {
			buf := NewBuffer(make([]byte, 0, 10))
			buf.Write([]byte{'f', 'o', 'o'})
			buf.Write([]byte{'b', 'a', 'r'})
			Expect(buf.String()).To(Equal("foobar"))
		})

		It("appends to a given slice", func() {
			data := make([]byte, 3, 6)
			data[0] = byte('f')
			data[1] = byte('o')
			data[2] = byte('o')
			buf := NewBuffer(data)
			buf.Write([]byte{'b', 'a', 'r'})
			Expect(buf.String()).To(Equal("foobar"))
		})

		It("panics when the underlying slice is too short", func() {
			buf := NewBuffer(make([]byte, 0, 5))
			buf.Write([]byte{'f', 'o', 'o'})
			Expect(func() { buf.Write([]byte{'b', 'a', 'r'}) }).Should(Panic())
		})
	})

	Context("length", func() {
		It("has 0 length in the beginning", func() {
			buf := NewBuffer(make([]byte, 0, 5))
			Expect(buf.Len()).To(BeZero())
		})

		It("returns the length", func() {
			buf := NewBuffer(make([]byte, 0, 5))
			buf.Write([]byte{'f', 'o', 'o'})
			Expect(buf.Len()).To(Equal(3))
		})
	})
})
