package utils

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Caching reader", func() {
	It("caches Read()", func() {
		r := bytes.NewReader([]byte("foobar"))
		cr := NewCachingReader(r)
		p := make([]byte, 3)
		n, err := cr.Read(p)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(3))
		Expect(p).To(Equal([]byte("foo")))
		Expect(cr.Get()).To(Equal([]byte("foo")))
	})

	It("caches ReadByte()", func() {
		r := bytes.NewReader([]byte("foobar"))
		cr := NewCachingReader(r)
		b, err := cr.ReadByte()
		Expect(err).ToNot(HaveOccurred())
		Expect(b).To(Equal(byte('f')))
		b, err = cr.ReadByte()
		Expect(err).ToNot(HaveOccurred())
		Expect(b).To(Equal(byte('o')))
		b, err = cr.ReadByte()
		Expect(err).ToNot(HaveOccurred())
		Expect(b).To(Equal(byte('o')))
		Expect(cr.Get()).To(Equal([]byte("foo")))
	})
})
