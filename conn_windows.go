// +build windows

package quic

import "net"

func newConn(c *net.UDPConn) (connection, error) {
	return &basicConn{PacketConn: c}, nil
}
