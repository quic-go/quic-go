package handshake

import (
	"io"
	"net"
	"time"
)

type cryptoStreamConn struct {
	io.ReadWriter
}

var _ net.Conn = &cryptoStreamConn{}

func newCryptoStreamConn(stream io.ReadWriter) net.Conn {
	return &cryptoStreamConn{
		ReadWriter: stream,
	}
}

// Close is not implemented
func (c *cryptoStreamConn) Close() error {
	return nil
}

// LocalAddr is not implemented
func (c *cryptoStreamConn) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr is not implemented
func (c *cryptoStreamConn) RemoteAddr() net.Addr {
	return nil
}

// SetReadDeadline is not implemented
func (c *cryptoStreamConn) SetReadDeadline(time.Time) error {
	return nil
}

// SetWriteDeadline is not implemented
func (c *cryptoStreamConn) SetWriteDeadline(time.Time) error {
	return nil
}

// SetDeadline is not implemented
func (c *cryptoStreamConn) SetDeadline(time.Time) error {
	return nil
}
