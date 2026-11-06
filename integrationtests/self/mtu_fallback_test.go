//go:build darwin || linux

package self_test

import (
	"context"
	"net"
	"strconv"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/udp"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

type mtuLimitedConn struct {
	*simnet.SimConn
}

var _ udp.Conn = &mtuLimitedConn{}

func (c *mtuLimitedConn) WritePacket(b []byte, addr net.Addr, oob []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	if len(b) > protocol.MinInitialPacketSize {
		return 0, syscall.EMSGSIZE
	}
	return c.SimConn.WritePacket(b, addr, oob, gsoSize, ecn)
}

func TestHandshakePacketSizeFallback(t *testing.T) {
	for _, initialSize := range []uint16{0, protocol.InitialPacketSize} {
		t.Run(strconv.Itoa(int(initialSize)), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				clientConn, serverConn, closeFn := newSimnetLink(t, 10*time.Millisecond)
				defer closeFn(t)

				config := getQuicConfig(&quic.Config{
					Versions:                []quic.Version{version},
					InitialPacketSize:       initialSize,
					DisablePathMTUDiscovery: true,
				})
				ln, err := quic.Listen(&mtuLimitedConn{SimConn: serverConn}, getTLSConfig(), config)
				require.NoError(t, err)
				defer ln.Close()

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				client, err := quic.Dial(ctx, &mtuLimitedConn{SimConn: clientConn}, ln.Addr(), getTLSClientConfig(), config)
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
		})
	}
}
