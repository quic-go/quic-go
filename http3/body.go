package http3

import (
	"context"
	"io"
	"net"

	"github.com/quic-go/quic-go"
)

// The HTTPStreamer allows taking over a HTTP/3 stream. The interface is implemented by:
// * for the server: the http.Request.Body
// * for the client: the http.Response.Body
// On the client side, the stream will be closed for writing, unless the DontCloseRequestStream RoundTripOpt was set.
// When a stream is taken over, it's the caller's responsibility to close the stream.
type HTTPStreamer interface {
	HTTPStream() Stream
}

type StreamCreator interface {
	// Context returns a context that is cancelled when the underlying connection is closed.
	Context() context.Context
	OpenStream() (quic.Stream, error)
	OpenStreamSync(context.Context) (quic.Stream, error)
	OpenUniStream() (quic.SendStream, error)
	OpenUniStreamSync(context.Context) (quic.SendStream, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	ConnectionState() quic.ConnectionState
}

var _ StreamCreator = quic.Connection(nil)

// A Hijacker allows hijacking of the stream creating part of a quic.Session from a http.Response.Body.
// It is used by WebTransport to create WebTransport streams after a session has been established.
type Hijacker interface {
	StreamCreator() StreamCreator
}

// Settingser allows the server to retrieve the client's SETTINGS.
// The http.Request.Body implements this interface.
type Settingser interface {
	// Settings returns the client's HTTP settings.
	// It blocks until the SETTINGS frame has been received.
	// Note that it is not guaranteed that this happens during the lifetime of the request.
	Settings(context.Context) (*Settings, error)
}

// The body is used in the requestBody (for a http.Request) and the responseBody (for a http.Response).
type body struct {
	str quic.Stream

	wasHijacked bool // set when HTTPStream is called
}

func (r *body) HTTPStream() Stream {
	r.wasHijacked = true
	return r.str
}

func (r *body) StreamID() quic.StreamID { return r.str.StreamID() }
func (r *body) wasStreamHijacked() bool {
	return r.wasHijacked
}

func (r *body) Read(b []byte) (int, error) {
	n, err := r.str.Read(b)
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

var (
	_ io.ReadCloser = &requestBody{}
	_ HTTPStreamer  = &requestBody{}
	_ Settingser    = &requestBody{}
)

func newRequestBody(str Stream, connCtx context.Context, rcvdSettings <-chan struct{}, getSettings func() *Settings) *requestBody {
	return &requestBody{
		body:         body{str: str},
		connCtx:      connCtx,
		rcvdSettings: rcvdSettings,
		getSettings:  getSettings,
	}
}

func (r *requestBody) Settings(ctx context.Context) (*Settings, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-r.connCtx.Done():
		return nil, context.Cause(r.connCtx)
	case <-r.rcvdSettings:
		return r.getSettings(), nil
	}
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

var (
	_ io.ReadCloser = &hijackableBody{}
	_ Hijacker      = &hijackableBody{}
	_ HTTPStreamer  = &hijackableBody{}
)

func newResponseBody(str Stream, conn quic.Connection, done chan<- struct{}) *hijackableBody {
	return &hijackableBody{
		body:    body{str: str},
		reqDone: done,
		conn:    conn,
	}
}

func (r *hijackableBody) Read(b []byte) (int, error) {
	n, err := r.str.Read(b)
	if err != nil {
		r.requestDone()
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

func (r *hijackableBody) Close() error {
	r.requestDone()
	// If the EOF was read, CancelRead() is a no-op.
	r.str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
	return nil
}

func (r *hijackableBody) HTTPStream() Stream           { return r.str }
func (r *hijackableBody) StreamCreator() StreamCreator { return r.conn }
