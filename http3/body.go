package http3

import (
	"io"

	"github.com/lucas-clemente/quic-go"
)

// onFrameError:
// Server: sess.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), "")
// Client: c.session.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), "")

// The body of a http.Request or http.Response.
type body struct {
	str RequestStream

	// only set for the http.Response
	// The channel is closed when the user is done with this response:
	// either when Read() errors, or when Close() is called.
	reqDone       chan<- struct{}
	reqDoneClosed bool

	onFrameError func()
}

var _ io.ReadCloser = &body{}

func newRequestBody(str RequestStream, onFrameError func()) *body {
	return &body{
		str:          str,
		onFrameError: onFrameError,
	}
}

func newResponseBody(str RequestStream, done chan<- struct{}, onFrameError func()) *body {
	return &body{
		str:          str,
		onFrameError: onFrameError,
		reqDone:      done,
	}
}

func (r *body) Read(p []byte) (n int, err error) {
	n, err = r.str.DataReader().Read(p)
	if err != nil {
		r.requestDone()
		if _, ok := err.(*FrameTypeError); ok {
			r.onFrameError()
		}
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
