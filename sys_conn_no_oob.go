//go:build !darwin && !linux && !freebsd && !windows

package quic

import (
	"net"
	"net/netip"

	"github.com/quic-go/quic-go/internal/protocol"
)

func newConn(c net.PacketConn, supportsDF bool) (*basicConn, error) {
	return &basicConn{PacketConn: c, supportsDF: supportsDF}, nil
}

func inspectReadBuffer(any) (int, error)  { return 0, nil }
func inspectWriteBuffer(any) (int, error) { return 0, nil }

func appendIPv4ECNMsg([]byte, protocol.ECN) []byte { return nil }
func appendIPv6ECNMsg([]byte, protocol.ECN) []byte { return nil }

type packetInfo struct {
	addr netip.Addr
}

func (i *packetInfo) OOB() []byte { return nil }
