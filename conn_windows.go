// +build windows

package quic

import "net"

func newConn(c net.PacketConn) (connection, error) {
	return &basicConn{PacketConn: c}, nil
}
