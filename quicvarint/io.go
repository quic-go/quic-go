package quicvarint

import (
	"bytes"
	"io"
)

// Reader implements both the io.ByteReader and io.Reader interfaces.
type Reader interface {
	io.ByteReader
	io.Reader
}

var _ Reader = &bytes.Reader{}

type reader struct {
	io.ByteReader
	io.Reader
}

var _ Reader = &reader{}

type byteReader struct {
	io.Reader
}

var _ Reader = &byteReader{}

// NewReader returns a Reader for r.
// If r already implements both io.ByteReader and io.Reader, NewReader returns r.
// Otherwise, r is wrapped to add the missing interfaces.
func NewReader(r io.Reader) Reader {
	if r, ok := r.(Reader); ok {
		return r
	}
	if br, ok := r.(io.ByteReader); ok {
		return &reader{br, r}
	}
	return &byteReader{r}
}

func (r *byteReader) ReadByte() (byte, error) {
	b := make([]byte, 1)
	_, err := r.Reader.Read(b)
	return b[0], err
}

// Writer implements both the io.ByteWriter and io.Writer interfaces.
type Writer interface {
	io.ByteWriter
	io.Writer
}

var _ Writer = &bytes.Buffer{}

type writer struct {
	io.ByteWriter
	io.Writer
}

var _ Writer = &writer{}

type byteWriter struct {
	io.Writer
}

var _ Writer = &byteWriter{}

// NewWriter returns a Writer for w.
// If r already implements both io.ByteWriter and io.Writer, NewWriter returns w.
// Otherwise, w is wrapped to add the missing interfaces.
func NewWriter(w io.Writer) Writer {
	if w, ok := w.(Writer); ok {
		return w
	}
	if bw, ok := w.(io.ByteWriter); ok {
		return &writer{bw, w}
	}
	return &byteWriter{w}
}

func (w *byteWriter) WriteByte(c byte) error {
	_, err := w.Writer.Write([]byte{c})
	return err
}
