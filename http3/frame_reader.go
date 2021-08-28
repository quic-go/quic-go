package http3

import "io"

// FrameReader implements a lightweight HTTP/3 frame reader.
// After setting R, an otherwise zero-value FrameReader is ready to use.
// A FrameReader can be initialized with an already-read frame header
// by setting Type and N.
type FrameReader struct {
	R    io.Reader
	Type FrameType
	N    int64
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
	return nil
}

// Read reads bytes from the current frame payload.
// It returns io.EOF at the end of the frame payload.
// It should not be called simultaneously with Next or WriteTo.
// The state of r is indeterminate after Read returns an error.
// Read conforms to io.Reader.
func (r *FrameReader) Read(p []byte) (n int, err error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	// TODO: implement read
	return 0, nil
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
