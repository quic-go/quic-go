package http3

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
)

// A Hijacker allows hijacking of the stream creating part of a quic.Session from a http.Response.Body.
// It is used by WebTransport to create WebTransport streams after a session has been established.
type Hijacker interface {
	Connection() Connection
}

var errTooMuchData = errors.New("peer sent too much data")

// The body is used in the requestBody (for a http.Request) and the responseBody (for a http.Response).
type body struct {
	str *stream

	remainingContentLength int64
	violatedContentLength  bool
	hasContentLength       bool
}

func newBody(str *stream, contentLength int64) *body {
	b := &body{str: str}
	if contentLength >= 0 {
		b.hasContentLength = true
		b.remainingContentLength = contentLength
	}
	return b
}

func (r *body) StreamID() quic.StreamID { return r.str.StreamID() }

func (r *body) checkContentLengthViolation() error {
	if !r.hasContentLength {
		return nil
	}
	if r.remainingContentLength < 0 || r.remainingContentLength == 0 && r.str.hasMoreData() {
		if !r.violatedContentLength {
			r.str.CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
			r.str.CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
			r.violatedContentLength = true
		}
		return errTooMuchData
	}
	return nil
}

func (r *body) Read(b []byte) (int, error) {
	if err := r.checkContentLengthViolation(); err != nil {
		return 0, err
	}
	if r.hasContentLength {
		b = b[:min(int64(len(b)), r.remainingContentLength)]
	}
	n, err := r.str.Read(b)
	r.remainingContentLength -= int64(n)
	if err := r.checkContentLengthViolation(); err != nil {
		return n, err
	}
	return n, maybeReplaceError(err)
}

func (r *body) Close() error {
	r.str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
	return nil
}

type requestBody struct {
	body
	connCtx      context.Context
	rcvdSettings <-chan struct{}
	getSettings  func() *Settings
}

var _ io.ReadCloser = &requestBody{}

func newRequestBody(str *stream, contentLength int64, connCtx context.Context, rcvdSettings <-chan struct{}, getSettings func() *Settings) *requestBody {
	return &requestBody{
		body:         *newBody(str, contentLength),
		connCtx:      connCtx,
		rcvdSettings: rcvdSettings,
		getSettings:  getSettings,
	}
}

type hijackableBody struct {
	body body

	// only set for the http.Response
	// The channel is closed when the user is done with this response:
	// either when Read() errors, or when Close() is called.
	reqDone       chan<- struct{}
	reqDoneClosed bool

	// used for parsing trailers
	str     *stream
	decoder *qpack.Decoder
	res     *http.Response
}

var _ io.ReadCloser = &hijackableBody{}

func newResponseBody(str *stream, contentLength int64, done chan<- struct{}, decoder *qpack.Decoder, res *http.Response) *hijackableBody {
	return &hijackableBody{
		body:    *newBody(str, contentLength),
		str:     str,
		reqDone: done,
		decoder: decoder,
		res:     res,
	}
}

func (r *hijackableBody) Read(b []byte) (int, error) {
	n, err := r.body.Read(b)
	if err != nil {
		r.requestDone()
	}
	if err == io.EOF {
		r.decodeTrailers()
	}
	return n, maybeReplaceError(err)
}

func (r *hijackableBody) requestDone() {
	if r.reqDoneClosed || r.reqDone == nil {
		return
	}
	if r.reqDone != nil {
		close(r.reqDone)
	}
	r.reqDoneClosed = true
}

func (r *hijackableBody) decodeTrailers() error {
	if r.str.trailersFrame == nil {
		return nil
	}
	fields, err := r.decoder.DecodeFull(r.str.trailersFrame)
	if err != nil {
		return err
	}
	r.res.Trailer = http.Header{}
	for _, field := range fields {
		r.res.Trailer.Add(field.Name, field.Value)
	}
	return nil
}

func (r *hijackableBody) Close() error {
	r.requestDone()
	// If the EOF was read, CancelRead() is a no-op.
	r.body.str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
	return nil
}
