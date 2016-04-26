package quic

import "net"

type connection interface {
	write([]byte) error
	setCurrentRemoteAddr(interface{})
}

type udpConn struct {
	conn        *net.UDPConn
	currentAddr *net.UDPAddr
}

var _ connection = &udpConn{}

func (c *udpConn) write(p []byte) error {
	_, err := c.conn.WriteToUDP(p, c.currentAddr)
	return err
}

func (c *udpConn) setCurrentRemoteAddr(addr interface{}) {
	c.currentAddr = addr.(*net.UDPAddr)
}
