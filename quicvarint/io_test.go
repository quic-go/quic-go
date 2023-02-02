package quicvarint

import (
	"bytes"
	"io"

	. "github.com/onsi/ginkgo/v2"
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

// eofReader is a reader that returns data and the io.EOF at the same time in the last Read call
type eofReader struct {
	Data []byte
	pos  int
}

func (r *eofReader) Read(b []byte) (int, error) {
	n := copy(b, r.Data[r.pos:])
	r.pos += n
	if r.pos >= len(r.Data) {
		return n, io.EOF
	}
	return n, nil
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

		Context("EOF handling", func() {
			It("eofReader works correctly", func() {
				r := &eofReader{Data: []byte("foobar")}
				b := make([]byte, 3)
				n, err := r.Read(b)
				Expect(n).To(Equal(3))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(b)).To(Equal("foo"))
				n, err = r.Read(b)
				Expect(n).To(Equal(3))
				Expect(err).To(MatchError(io.EOF))
				Expect(string(b)).To(Equal("bar"))
				n, err = r.Read(b)
				Expect(err).To(MatchError(io.EOF))
				Expect(n).To(BeZero())
			})

			It("correctly handles io.EOF", func() {
				r := NewReader(&eofReader{Data: Append(nil, 1337)})
				n, err := Read(r)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(BeEquivalentTo(1337))
			})
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
