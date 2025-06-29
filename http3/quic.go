package http3

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type QUICSendStream interface {
	StreamID() quic.StreamID
	io.WriteCloser
	CancelWrite(quic.StreamErrorCode)
	SetWriteDeadline(time.Time) error
}

var _ QUICSendStream = &quic.SendStream{}

type QUICReceiveStream interface {
	StreamID() quic.StreamID
	io.Reader
	CancelRead(quic.StreamErrorCode)
	SetReadDeadline(time.Time) error
}

var _ QUICReceiveStream = &quic.ReceiveStream{}

type QUICStream interface {
	QUICSendStream
	QUICReceiveStream
	Context() context.Context
	SetDeadline(time.Time) error
}

var _ QUICStream = &quic.Stream{}

type QUICConn interface {
	OpenStream() (QUICStream, error)
	OpenStreamSync(context.Context) (QUICStream, error)
	OpenUniStream() (QUICSendStream, error)
	OpenUniStreamSync(context.Context) (QUICSendStream, error)
	AcceptStream(context.Context) (QUICStream, error)
	AcceptUniStream(context.Context) (QUICReceiveStream, error)

	Context() context.Context
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	CloseWithError(quic.ApplicationErrorCode, string) error
	ConnectionState() quic.ConnectionState
	HandshakeComplete() <-chan struct{}
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

type connAdapter struct {
	*quic.Conn
}

func (c *connAdapter) OpenStream() (QUICStream, error) {
	return c.OpenStream()
}

func (c *connAdapter) OpenStreamSync(ctx context.Context) (QUICStream, error) {
	return c.OpenStreamSync(ctx)
}

func (c *connAdapter) OpenUniStream() (QUICSendStream, error) {
	return c.OpenUniStream()
}

func (c *connAdapter) OpenUniStreamSync(ctx context.Context) (QUICSendStream, error) {
	return c.OpenUniStreamSync(ctx)
}

func (c *connAdapter) AcceptStream(ctx context.Context) (QUICStream, error) {
	return c.AcceptStream(ctx)
}

func (c *connAdapter) AcceptUniStream(ctx context.Context) (QUICReceiveStream, error) {
	return c.AcceptUniStream(ctx)
}

// A QUICListener listens for incoming QUIC connections.
type QUICListener interface {
	Accept(context.Context) (QUICConn, error)
	Addr() net.Addr
	io.Closer
}

type quicListenerAdapter struct {
	*quic.EarlyListener
}

func (l *quicListenerAdapter) Accept(ctx context.Context) (QUICConn, error) {
	conn, err := l.EarlyListener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &connAdapter{conn}, nil
}
