package self_test

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/synctest"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

func TestPacketDrops(t *testing.T) {
	for _, direction := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		t.Run(fmt.Sprintf("from %s", direction), func(t *testing.T) {
			testPacketDrops(t, direction)
		})
	}
}

func testPacketDrops(t *testing.T, direction protocol.Perspective) {
	synctest.Test(t, func(t *testing.T) {
		const numMessages = 50
		const rtt = 10 * time.Millisecond

		addrClient := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
		addrServer := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}

		var numDroppedPackets atomic.Int32
		messageInterval := randomDuration(10*time.Millisecond, 100*time.Millisecond)
		dropDuration := randomDuration(messageInterval*3, 2*time.Second)
		dropDelay := randomDuration(25*time.Millisecond, numMessages*messageInterval/2)

		startTime := time.Now()
		n := &simnet.Simnet{
			Router: &droppingRouter{
				Drop: func(p simnet.Packet) bool {
					switch p.To {
					case addrClient:
						if direction == protocol.PerspectiveClient {
							return false
						}
					case addrServer:
						if direction == protocol.PerspectiveServer {
							return false
						}
					}
					if wire.IsLongHeaderPacket(p.Data[0]) { // don't interfere with the handshake
						return false
					}
					drop := time.Now().After(startTime.Add(dropDelay)) && time.Now().Before(startTime.Add(dropDelay).Add(dropDuration))
					if drop {
						numDroppedPackets.Add(1)
					}
					return drop
				},
			},
		}
		settings := simnet.NodeBiDiLinkSettings{
			Downlink: simnet.LinkSettings{BitsPerSecond: 1e8},
			Uplink:   simnet.LinkSettings{BitsPerSecond: 1e8},
			Latency:  rtt / 2, // Latency applies to downlink only; uplink is instant
		}
		clientPacketConn := n.NewEndpoint(addrClient, settings)
		defer clientPacketConn.Close()
		serverPacketConn := n.NewEndpoint(addrServer, settings)
		defer serverPacketConn.Close()

		require.NoError(t, n.Start())
		defer n.Close()

		t.Logf("sending a message every %s, %d times", messageInterval, numMessages)
		t.Logf("dropping packets for %s, after a delay of %s", dropDuration, dropDelay)

		ln, err := quic.Listen(serverPacketConn, getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := quic.Dial(ctx, clientPacketConn, ln.Addr().(*net.UDPAddr), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")

		serverConn, err := ln.Accept(ctx)
		require.NoError(t, err)
		defer serverConn.CloseWithError(0, "")
		serverStr, err := serverConn.OpenUniStream()
		require.NoError(t, err)
		errChan := make(chan error, 1)
		go func() {
			for i := range numMessages {
				time.Sleep(messageInterval)
				if _, err := serverStr.Write([]byte{uint8(i + 1)}); err != nil {
					errChan <- err
					return
				}
			}
		}()

		str, err := conn.AcceptUniStream(ctx)
		require.NoError(t, err)
		for i := range numMessages {
			b := []byte{0}
			n, err := str.Read(b)
			require.NoError(t, err)
			require.Equal(t, 1, n)
			require.Equal(t, byte(i+1), b[0])
		}
		numDropped := numDroppedPackets.Load()
		t.Logf("dropped %d packets", numDropped)
		require.NotZero(t, numDropped)
	})
}
