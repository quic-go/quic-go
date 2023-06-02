//go:build !darwin && !linux && !freebsd && !windows

package quic

import "net"

func newConn(c net.PacketConn, supportsDF bool) (rawConn, error) {
	return &basicConn{PacketConn: c, supportsDF: supportsDF}, nil
}

func inspectReadBuffer(any) (int, error)  { return 0, nil }
func inspectWriteBuffer(any) (int, error) { return 0, nil }

func (i *packetInfo) OOB() []byte { return nil }
