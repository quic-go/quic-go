package quic

import (
	"net"
	"testing"

	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

func TestClosedLocalConnection(t *testing.T) {
	written := make(chan net.Addr, 1)
	conn := newClosedLocalConn(func(addr net.Addr, _ packetInfo) { written <- addr }, utils.DefaultLogger)
	addr := &net.UDPAddr{IP: net.IPv4(127, 1, 2, 3), Port: 1337}
	for i := 1; i <= 20; i++ {
		conn.handlePacket(receivedPacket{remoteAddr: addr})
		if i == 1 || i == 2 || i == 4 || i == 8 || i == 16 {
			select {
			case gotAddr := <-written:
				require.Equal(t, addr, gotAddr) // receive the CONNECTION_CLOSE
			default:
				t.Fatal("expected to receive address")
			}
		} else {
			select {
			case gotAddr := <-written:
				t.Fatalf("unexpected address received: %v", gotAddr)
			default:
				// Nothing received, which is expected
			}
		}
	}
}
