package http3

import (
	"io"

	"github.com/lucas-clemente/quic-go"
	"github.com/marten-seemann/qpack"
)

type trailerFunc func([]qpack.HeaderField, error)

// The body of a http.Request or http.Response.
type body struct {
	str RequestStream

	// only set for the http.Response
	// The channel is closed when the user is done with this response:
	// either when Read() errors, or when Close() is called.
	reqDone       chan<- struct{}
	reqDoneClosed bool

	onTrailers   trailerFunc
	onFrameError func()
}

var _ io.ReadCloser = &body{}

func newRequestBody(str RequestStream, onTrailers trailerFunc, onFrameError func()) *body {
	return &body{
		str:          str,
		onTrailers:   onTrailers,
		onFrameError: onFrameError,
	}
}

func newResponseBody(str RequestStream, onTrailers trailerFunc, done chan<- struct{}, onFrameError func()) *body {
	return &body{
		str:          str,
		onTrailers:   onTrailers,
		onFrameError: onFrameError,
		reqDone:      done,
	}
}

func (r *body) Read(p []byte) (n int, err error) {
	n, err = r.str.DataReader().Read(p)
	if err != nil {
		// Read trailers if present
		if err == io.EOF && r.onTrailers != nil {
			r.onTrailers(r.str.ReadHeaders())
		} else if _, ok := err.(*FrameTypeError); ok {
			r.onFrameError()
		}
		r.requestDone()
	}
	return n, err
}

func (r *body) requestDone() {
	if r.reqDoneClosed || r.reqDone == nil {
		return
	}
	close(r.reqDone)
	r.reqDoneClosed = true
}

func (r *body) Close() error {
	r.requestDone()
	// If the EOF was read, CancelRead() is a no-op.
	r.str.CancelRead(quic.StreamErrorCode(errorRequestCanceled))
	return nil
}
