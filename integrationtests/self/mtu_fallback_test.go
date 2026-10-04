//go:build darwin || linux

package self_test

import (
	"context"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

type mtuLimitedUDPConn struct {
	*net.UDPConn
}

var _ quic.OOBCapablePacketConn = &mtuLimitedUDPConn{}

func (c *mtuLimitedUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	if len(b) > protocol.MinInitialPacketSize {
		return 0, 0, syscall.EMSGSIZE
	}
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func TestHandshakePacketSizeFallback(t *testing.T) {
	// The wrapper limits individual datagrams, not GSO batches.
	t.Setenv("QUIC_GO_DISABLE_GSO", "true")
	for _, initialSize := range []uint16{0, protocol.InitialPacketSize} {
		t.Run(strconv.Itoa(int(initialSize)), func(t *testing.T) {
			serverUDP := &mtuLimitedUDPConn{UDPConn: newUDPConnLocalhost(t)}
			clientUDP := &mtuLimitedUDPConn{UDPConn: newUDPConnLocalhost(t)}
			config := getQuicConfig(&quic.Config{
				Versions:                []quic.Version{version},
				InitialPacketSize:       initialSize,
				DisablePathMTUDiscovery: true,
			})
			ln, err := quic.Listen(serverUDP, getTLSConfig(), config)
			require.NoError(t, err)
			defer ln.Close()

			ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(5*time.Second))
			defer cancel()
			client, err := quic.Dial(ctx, clientUDP, ln.Addr(), getTLSClientConfig(), config)
			if initialSize != 0 {
				require.ErrorContains(t, err, syscall.EMSGSIZE.Error())
				return
			}
			require.NoError(t, err)
			defer client.CloseWithError(0, "")
			server, err := ln.Accept(ctx)
			require.NoError(t, err)
			defer server.CloseWithError(0, "")
		})
	}
}
