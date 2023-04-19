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

	capabilities() connCapabilities
}

type sconn struct {
	rawConn

	remoteAddr net.Addr
	info       *packetInfo
	oob        []byte
}

var _ sendConn = &sconn{}

func newSendConn(c rawConn, remote net.Addr, info *packetInfo) *sconn {
	oob := info.OOB()
	if c.capabilities().GSO {
		// add 32 bytes, so we can add the UDP_SEGMENT msg
		l := len(oob)
		oob = append(oob, make([]byte, 32)...)
		oob = oob[:l]
	}
	return &sconn{
		rawConn:    c,
		remoteAddr: remote,
		info:       info,
		oob:        oob,
	}
}

func (c *sconn) Write(p []byte) error {
	_, err := c.WritePacket(p, c.remoteAddr, c.oob)
	return err
}

func (c *sconn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *sconn) LocalAddr() net.Addr {
	addr := c.rawConn.LocalAddr()
	if c.info != nil {
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			addrCopy := *udpAddr
			addrCopy.IP = c.info.addr
			addr = &addrCopy
		}
	}
	return addr
}
