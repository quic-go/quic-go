package http3

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptrace"
	"net/textproto"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

func traceGetConn(trace *httptrace.ClientTrace, hostPort string) {
	if trace != nil && trace.GetConn != nil {
		trace.GetConn(hostPort)
	}
}

// fakeConn is a wrapper for quic.EarlyConnection
// because the quic connection does not implement net.Conn.
type fakeConn struct {
	conn quic.EarlyConnection
}

func (c *fakeConn) Close() error                       { panic("connection operation prohibited") }
func (c *fakeConn) Read(p []byte) (int, error)         { panic("connection operation prohibited") }
func (c *fakeConn) Write(p []byte) (int, error)        { panic("connection operation prohibited") }
func (c *fakeConn) SetDeadline(t time.Time) error      { panic("connection operation prohibited") }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { panic("connection operation prohibited") }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { panic("connection operation prohibited") }
func (c *fakeConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *fakeConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }

func traceGotConn(trace *httptrace.ClientTrace, conn quic.EarlyConnection, reused bool) {
	if trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{
			Conn:   &fakeConn{conn: conn},
			Reused: reused,
		})
	}
}

func traceGotFirstResponseByte(trace *httptrace.ClientTrace) {
	if trace != nil && trace.GotFirstResponseByte != nil {
		trace.GotFirstResponseByte()
	}
}

func traceGot1xxResponse(trace *httptrace.ClientTrace, code int, header textproto.MIMEHeader) {
	if trace != nil && trace.Got1xxResponse != nil {
		trace.Got1xxResponse(code, header)
	}
}

func traceGot100Continue(trace *httptrace.ClientTrace) {
	if trace != nil && trace.Got100Continue != nil {
		trace.Got100Continue()
	}
}

func traceHasWroteHeaderField(trace *httptrace.ClientTrace) bool {
	return trace != nil && trace.WroteHeaderField != nil
}

func traceWroteHeaderField(trace *httptrace.ClientTrace, k, v string) {
	if trace != nil && trace.WroteHeaderField != nil {
		trace.WroteHeaderField(k, []string{v})
	}
}

func traceWroteHeaders(trace *httptrace.ClientTrace) {
	if trace != nil && trace.WroteHeaders != nil {
		trace.WroteHeaders()
	}
}

func traceWroteRequest(trace *httptrace.ClientTrace, err error) {
	if trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{Err: err})
	}
}

func traceConnectStart(trace *httptrace.ClientTrace, network, addr string) {
	if trace != nil && trace.ConnectStart != nil {
		trace.ConnectStart(network, addr)
	}
}

func traceConnectDone(trace *httptrace.ClientTrace, network, addr string, err error) {
	if trace != nil && trace.ConnectDone != nil {
		trace.ConnectDone(network, addr, err)
	}
}

func traceTLSHandshakeStart(trace *httptrace.ClientTrace) {
	if trace != nil && trace.TLSHandshakeStart != nil {
		trace.TLSHandshakeStart()
	}
}

type traceTLSOnceCtxKey string

const traceTLSOnceCtxKeyVal traceTLSOnceCtxKey = "http3.traceTLSOnce"

func withTraceTLSOnce(ctx context.Context, once *sync.Once) context.Context {
	return context.WithValue(ctx, traceTLSOnceCtxKeyVal, once)
}

func contextTraceTLSOnce(ctx context.Context) *sync.Once {
	if v := ctx.Value(traceTLSOnceCtxKeyVal); v != nil {
		return v.(*sync.Once)
	}
	return nil
}

func traceTLSHandshakeDone(trace *httptrace.ClientTrace, once *sync.Once, state tls.ConnectionState, err error) {
	if once != nil && trace != nil && trace.TLSHandshakeDone != nil {
		once.Do(func() { trace.TLSHandshakeDone(state, err) })
	}
}
