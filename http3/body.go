package http3

import (
	"context"
	"io"
	"net"

	"github.com/lucas-clemente/quic-go"
)

type StreamCreator interface {
	OpenStream() (quic.Stream, error)
	OpenStreamSync(context.Context) (quic.Stream, error)
	OpenUniStream() (quic.SendStream, error)
	OpenUniStreamSync(context.Context) (quic.SendStream, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

var _ StreamCreator = quic.Connection(nil)

// A Hijacker allows hijacking of the stream creating part of a quic.Session from a http.Response.Body.
// It is used by WebTransport to create WebTransport streams after a session has been established.
type Hijacker interface {
	StreamCreator() StreamCreator
}

// The body of a http.Request or http.Response.
type body struct {
	str quic.Stream
}

var _ io.ReadCloser = &body{}

func newRequestBody(str Stream) *body {
	return &body{str: str}
}

func (r *body) Read(b []byte) (int, error) {
	return r.str.Read(b)
}

func (r *body) Close() error {
	r.str.CancelRead(quic.StreamErrorCode(errorRequestCanceled))
	return nil
}

type hijackableBody struct {
	body
	conn quic.Connection // only needed to implement Hijacker

	// only set for the http.Response
	// The channel is closed when the user is done with this response:
	// either when Read() errors, or when Close() is called.
	reqDone       chan<- struct{}
	reqDoneClosed bool
}

var _ Hijacker = &hijackableBody{}

func newResponseBody(str Stream, conn quic.Connection, done chan<- struct{}) *hijackableBody {
	return &hijackableBody{
		body: body{
			str: str,
		},
		reqDone: done,
		conn:    conn,
	}
}

func (r *hijackableBody) StreamCreator() StreamCreator {
	return r.conn
}

func (r *hijackableBody) Read(b []byte) (int, error) {
	n, err := r.str.Read(b)
	if err != nil {
		r.requestDone()
	}
	return n, err
}

func (r *hijackableBody) requestDone() {
	if r.reqDoneClosed || r.reqDone == nil {
		return
	}
	close(r.reqDone)
	r.reqDoneClosed = true
}

func (r *body) StreamID() quic.StreamID {
	return r.str.StreamID()
}

func (r *hijackableBody) Close() error {
	r.requestDone()
	// If the EOF was read, CancelRead() is a no-op.
	r.str.CancelRead(quic.StreamErrorCode(errorRequestCanceled))
	return nil
}
