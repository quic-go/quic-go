package http3

import (
	"io"
	"net/http"

	"github.com/lucas-clemente/quic-go"
)

// onFrameError:
// Server: sess.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), "")
// Client: c.session.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), "")

// The body of a http.Request or http.Response.
type body struct {
	str RequestStream

	trailer http.Header

	// only set for the http.Response
	// The channel is closed when the user is done with this response:
	// either when Read() errors, or when Close() is called.
	reqDone       chan<- struct{}
	reqDoneClosed bool

	onFrameError func()
}

var _ io.ReadCloser = &body{}

func newRequestBody(str RequestStream, trailer http.Header, onFrameError func()) *body {
	return &body{
		str:          str,
		trailer:      trailer,
		onFrameError: onFrameError,
	}
}

func newResponseBody(str RequestStream, trailer http.Header, done chan<- struct{}, onFrameError func()) *body {
	return &body{
		str:          str,
		trailer:      trailer,
		onFrameError: onFrameError,
		reqDone:      done,
	}
}

func (r *body) Read(p []byte) (n int, err error) {
	n, err = r.str.DataReader().Read(p)
	if err != nil {
		// Read trailers if present
		if err == io.EOF && r.trailer != nil {
			fields, ferr := r.str.ReadHeaders()
			if ferr != nil {
				// TODO(ydnar): log this error
			} else {
				for _, f := range fields {
					r.trailer.Add(f.Name, f.Value)
				}
			}
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
