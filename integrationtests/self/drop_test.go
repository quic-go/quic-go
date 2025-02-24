package self_test

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestDropTests(t *testing.T) {
	for _, direction := range []quicproxy.Direction{quicproxy.DirectionIncoming, quicproxy.DirectionOutgoing} {
		t.Run(fmt.Sprintf("in %s direction", direction), func(t *testing.T) {
			const numMessages = 15
			const rtt = 10 * time.Millisecond

			messageInterval := randomDuration(10*time.Millisecond, 100*time.Millisecond)
			dropDuration := randomDuration(messageInterval*3/2, 2*time.Second)
			dropDelay := randomDuration(25*time.Millisecond, numMessages*messageInterval/2)
			t.Logf("sending a message every %s, %d times", messageInterval, numMessages)
			t.Logf("dropping packets for %s, after a delay of %s", dropDuration, dropDelay)
			startTime := time.Now()

			ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
			require.NoError(t, err)
			defer ln.Close()

			var numDroppedPackets atomic.Int32
			proxy := &quicproxy.Proxy{
				Conn:        newUDPConnLocalhost(t),
				ServerAddr:  ln.Addr().(*net.UDPAddr),
				DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration { return rtt / 2 },
				DropPacket: func(d quicproxy.Direction, _, _ net.Addr, b []byte) bool {
					if !d.Is(direction) {
						return false
					}
					if wire.IsLongHeaderPacket(b[0]) { // don't interfere with the handshake
						return false
					}
					drop := time.Now().After(startTime.Add(dropDelay)) && time.Now().Before(startTime.Add(dropDelay).Add(dropDuration))
					if drop {
						numDroppedPackets.Add(1)
					}
					return drop
				},
			}
			require.NoError(t, proxy.Start())
			defer proxy.Close()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")

			serverConn, err := ln.Accept(ctx)
			require.NoError(t, err)
			serverStr, err := serverConn.OpenUniStream()
			require.NoError(t, err)
			errChan := make(chan error, 1)
			go func() {
				for i := uint8(1); i <= numMessages; i++ {
					if _, err := serverStr.Write([]byte{i}); err != nil {
						errChan <- err
						return
					}
					time.Sleep(messageInterval)
				}
			}()

			str, err := conn.AcceptUniStream(ctx)
			require.NoError(t, err)
			for i := uint8(1); i <= numMessages; i++ {
				b := []byte{0}
				n, err := str.Read(b)
				require.NoError(t, err)
				require.Equal(t, 1, n)
				require.Equal(t, i, b[0])
			}
			numDropped := numDroppedPackets.Load()
			t.Logf("dropped %d packets", numDropped)
			require.NotZero(t, numDropped)
		})
	}
}
