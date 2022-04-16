package http3

import (
	"context"
	"fmt"
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

	// only set for the http.Response
	// The channel is closed when the user is done with this response:
	// either when Read() errors, or when Close() is called.
	reqDone       chan<- struct{}
	reqDoneClosed bool

	onFrameError func()

	bytesRemainingInFrame uint64
}

var _ io.ReadCloser = &body{}

type hijackableBody struct {
	body
	conn quic.Connection // only needed to implement Hijacker
}

var _ Hijacker = &hijackableBody{}

func newRequestBody(str quic.Stream, onFrameError func()) *body {
	return &body{
		str:          str,
		onFrameError: onFrameError,
	}
}

func newResponseBody(str quic.Stream, conn quic.Connection, done chan<- struct{}, onFrameError func()) *hijackableBody {
	return &hijackableBody{
		body: body{
			str:          str,
			onFrameError: onFrameError,
			reqDone:      done,
		},
		conn: conn,
	}
}

func (r *hijackableBody) StreamCreator() StreamCreator {
	return r.conn
}

func (r *body) Read(b []byte) (int, error) {
	n, err := r.readImpl(b)
	if err != nil {
		r.requestDone()
	}
	return n, err
}

func (r *body) readImpl(b []byte) (int, error) {
	if r.bytesRemainingInFrame == 0 {
	parseLoop:
		for {
			frame, err := parseNextFrame(r.str, nil)
			if err != nil {
				return 0, err
			}
			switch f := frame.(type) {
			case *headersFrame:
				// skip HEADERS frames
				continue
			case *dataFrame:
				r.bytesRemainingInFrame = f.Length
				break parseLoop
			default:
				r.onFrameError()
				// parseNextFrame skips over unknown frame types
				// Therefore, this condition is only entered when we parsed another known frame type.
				return 0, fmt.Errorf("peer sent an unexpected frame: %T", f)
			}
		}
	}

	var n int
	var err error
	if r.bytesRemainingInFrame < uint64(len(b)) {
		n, err = r.str.Read(b[:r.bytesRemainingInFrame])
	} else {
		n, err = r.str.Read(b)
	}
	r.bytesRemainingInFrame -= uint64(n)
	return n, err
}

func (r *body) requestDone() {
	if r.reqDoneClosed || r.reqDone == nil {
		return
	}
	close(r.reqDone)
	r.reqDoneClosed = true
}

func (r *body) StreamID() quic.StreamID {
	return r.str.StreamID()
}

func (r *body) Close() error {
	r.requestDone()
	// If the EOF was read, CancelRead() is a no-op.
	r.str.CancelRead(quic.StreamErrorCode(errorRequestCanceled))
	return nil
}
