//go:build !darwin && !linux && !freebsd && !windows && !openbsd

package udp

import (
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
)

func newConn(c net.PacketConn, supportsDF bool, maxPacketSize protocol.ByteCount) (*basicConn, error) {
	return &basicConn{PacketConn: c, supportsDF: supportsDF, maxPacketSize: maxPacketSize}, nil
}

func inspectReadBuffer(any) (int, error)  { return 0, nil }
func inspectWriteBuffer(any) (int, error) { return 0, nil }

const desiredBufferSize = 7 << 20 // 7 MiB
