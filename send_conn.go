package quic

import (
	"net"
)

// A sendConn allows sending using a simple Write() on a non-connected packet conn.
type sendConn interface {
	Write([]byte) error
	WritePackets([][]byte) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type sconn struct {
	raw rawSendConn

	remoteAddr net.Addr
	info       *packetInfo
	oob        []byte
}

var _ sendConn = &sconn{}

func newSendConn(c rawConn, remote net.Addr, info *packetInfo) sendConn {
	return &sconn{
		raw:        c.newSendConn(),
		remoteAddr: remote,
		info:       info,
		oob:        info.OOB(),
	}
}

func (c *sconn) Write(p []byte) error {
	_, err := c.raw.WritePacket(p, c.remoteAddr, c.oob)
	return err
}

func (c *sconn) WritePackets(p [][]byte) error {
	_, err := c.raw.WritePackets(p, c.remoteAddr, c.oob)
	return err
}

func (c *sconn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *sconn) LocalAddr() net.Addr {
	addr := c.raw.LocalAddr()
	if c.info != nil {
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			addrCopy := *udpAddr
			addrCopy.IP = c.info.addr
			addr = &addrCopy
		}
	}
	return addr
}

func (c *sconn) Close() error {
	return c.raw.Close()
}
