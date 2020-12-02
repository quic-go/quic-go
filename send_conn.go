package quic

import (
	"net"
)

// A sendConn allows sending using a simple Write() on a non-connected packet conn.
type sendConn interface {
	Write([]byte) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type sconn struct {
	net.PacketConn

	remoteAddr net.Addr
}

var _ sendConn = &sconn{}

func newSendConn(c net.PacketConn, remote net.Addr) sendConn {
	return &sconn{PacketConn: c, remoteAddr: remote}
}

func (c *sconn) Write(p []byte) error {
	_, err := c.PacketConn.WriteTo(p, c.remoteAddr)
	return err
}

func (c *sconn) RemoteAddr() net.Addr {
	return c.remoteAddr
}
