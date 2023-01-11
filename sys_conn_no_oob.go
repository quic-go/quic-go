//go:build !darwin && !linux && !freebsd && !windows

package quic

import "net"

func newConn(c net.PacketConn, pool *packetBufferPool) (rawConn, error) {
	return &basicConn{
		PacketConn: c,
		pool:       pool,
	}, nil
}

func inspectReadBuffer(interface{}) (int, error) {
	return 0, nil
}

func (i *packetInfo) OOB() []byte { return nil }
