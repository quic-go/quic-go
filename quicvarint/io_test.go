package quicvarint

import (
	"bytes"
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type nopReader struct{}

func (r *nopReader) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

var _ io.Reader = &nopReader{}

type nopWriter struct{}

func (r *nopWriter) Write(_ []byte) (int, error) {
	return 0, io.ErrShortBuffer
}

var _ io.Writer = &nopWriter{}

var _ = Describe("Varint I/O", func() {
	Context("Reader", func() {
		Context("NewReader", func() {
			It("passes through a Reader unchanged", func() {
				b := bytes.NewReader([]byte{0})
				r := NewReader(b)
				Expect(r).To(Equal(b))
			})

			It("wraps an io.Reader", func() {
				n := &nopReader{}
				r := NewReader(n)
				Expect(r).ToNot(Equal(n))
			})
		})

		It("returns an error when reading from an underlying io.Reader fails", func() {
			r := NewReader(&nopReader{})
			val, err := r.ReadByte()
			Expect(err).To(Equal(io.ErrUnexpectedEOF))
			Expect(val).To(Equal(byte(0)))
		})
	})

	Context("Writer", func() {
		Context("NewWriter", func() {
			It("passes through a Writer unchanged", func() {
				b := &bytes.Buffer{}
				w := NewWriter(b)
				Expect(w).To(Equal(b))
			})

			It("wraps an io.Writer", func() {
				n := &nopWriter{}
				w := NewWriter(n)
				Expect(w).ToNot(Equal(n))
			})
		})

		It("returns an error when writing to an underlying io.Writer fails", func() {
			w := NewWriter(&nopWriter{})
			err := w.WriteByte(0)
			Expect(err).To(Equal(io.ErrShortBuffer))
		})
	})
})
