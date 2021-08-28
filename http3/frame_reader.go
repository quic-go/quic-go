package http3

import (
	"io"

	"github.com/lucas-clemente/quic-go/quicvarint"
)

// FrameReader implements a lightweight HTTP/3 frame reader.
// After setting R, an otherwise zero-value FrameReader is ready to use.
// If a frame has already been partially read from R, a FrameReader
// can be initialized by setting Type to the current frame type and N to
// the number of bytes remaining in the payload.
type FrameReader struct {
	R    io.Reader
	Type FrameType
	N    int64
	r    io.Reader
	qr   quicvarint.Reader
}

var (
	_ io.Reader   = &FrameReader{}
	_ io.WriterTo = &FrameReader{}
)

// Next advances r to the next frame.
// Unconsumed bytes on the current frame, if any, will be discarded.
// It returns any error encountered when reading from the underlying io.Reader.
// If successful, r.Type will be set to the current frame type, and r.N will
// be set to the length of the current frame payload.
// N will decrement towards 0 as the frame payload is read.
// The state of r is indeterminate if Next returns an error.
func (r *FrameReader) Next() error {
	if r.N > 0 {
		n, err := io.CopyN(io.Discard, r.R, r.N)
		r.N -= n
		if err != nil {
			return err
		}
	}
	if r.r != r.R {
		r.r = r.R
		r.qr = quicvarint.NewReader(r.r)
	}
	i, err := quicvarint.Read(r.qr)
	r.Type = FrameType(i)
	if err != nil {
		return err
	}
	i, err = quicvarint.Read(r.qr)
	r.N = int64(i)
	return err
}

// Read reads bytes from the current frame payload.
// It will read up to len(p) or r.N, whichever is smaller.
// It returns io.EOF if bytes remaining in the frame payload <= 0.
// It should not be called simultaneously with Next or WriteTo.
// The state of r is indeterminate after Read returns an error.
// Read conforms to io.Reader.
func (r *FrameReader) Read(p []byte) (n int, err error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.N {
		p = p[:r.N]
	}
	n, err = r.R.Read(p)
	r.N -= int64(n)
	return n, err
}

// WriteTo writes any remaining bytes of the current frame payload to w.
// It returns any error encountered reading the frame payload or writing to w.
// It returns io.EOF if there are no bytes remaining in the current frame.
// It should not be called simultaneously with Next or Read.
// The state of r is indeterminate after WriteTo returns an error.
// WriteTo conforms to io.WriterTo.
func (r *FrameReader) WriteTo(w io.Writer) (n int64, err error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	n, err = io.CopyN(w, r.R, r.N)
	r.N -= n
	return n, err
}
