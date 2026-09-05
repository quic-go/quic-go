package quic

import (
	"fmt"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestConnectionHandshakePacketSizeFallback(t *testing.T) {
	for _, perspective := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		for _, receivedParams := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/received parameters: %t", perspective, receivedParams), func(t *testing.T) {
				config := &Config{InitialPacketSize: 1337}
				var tc *testConnection
				if perspective == protocol.PerspectiveClient {
					tc = newClientTestConnection(t, nil, config, false)
				} else {
					tc = newServerTestConnection(t, nil, config, false)
				}
				c := tc.conn
				c.rttStats.UpdateRTT(10*time.Millisecond, 0)
				c.peerParams = &wire.TransportParameters{MaxUDPPayloadSize: 1400, ActiveConnectionIDLimit: 2}
				if receivedParams {
					c.applyTransportParameters()
					require.Equal(t, protocol.ByteCount(1337), c.maxPacketSize())
				} else {
					require.Nil(t, c.mtuDiscoverer)
				}
				c.handleSendMsgSizeError()
				require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), c.maxPacketSize())
				require.Equal(t, uint32(estimateMaxPayloadSize(protocol.MinInitialPacketSize)), c.maxPayloadSizeEstimate.Load())
				require.Equal(t, uint16(1337), c.config.InitialPacketSize)
				if !receivedParams {
					c.applyTransportParameters()
				}
				require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), c.mtuDiscoverer.CurrentSize())
				require.Equal(t, protocol.ByteCount(1400), c.mtuDiscoverer.max())
				require.False(t, c.mtuDiscoverer.ShouldSendProbe(monotime.Now().Add(time.Hour)))

				// Repeated notifications at the minimum don't reset discovery or shrink further.
				finder := c.mtuDiscoverer
				c.handleSendMsgSizeError()
				require.Same(t, finder, c.mtuDiscoverer)
				require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), c.maxPacketSize())

				// Confirmation preserves the fallback, then normal probing can grow it.
				c.handshakeConfirmed = true
				now := monotime.Now()
				finder.Start(now)
				require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), c.maxPacketSize())
				require.True(t, finder.ShouldSendProbe(now.Add(time.Second)))
				probe, size := finder.GetPing(now.Add(time.Second))
				c.handleSendMsgSizeError()
				require.Same(t, finder, c.mtuDiscoverer)
				probe.Handler.OnAcked(probe.Frame)
				require.Equal(t, size, c.maxPacketSize())
				require.Greater(t, size, protocol.ByteCount(protocol.MinInitialPacketSize))
			})
		}
	}
}

func TestConnectionSendMessageTooLargeAfterHandshake(t *testing.T) {
	tc := newClientTestConnection(t, nil, &Config{InitialPacketSize: 1337}, false, connectionOptHandshakeConfirmed())
	c := tc.conn
	c.peerParams = &wire.TransportParameters{MaxUDPPayloadSize: 1450, ActiveConnectionIDLimit: 2}
	c.applyTransportParameters()
	finder := c.mtuDiscoverer
	finder.Start(monotime.Now())
	probe, size := finder.GetPing(monotime.Now().Add(time.Second))
	c.handleSendMsgSizeError()
	require.Same(t, finder, c.mtuDiscoverer)
	require.Equal(t, protocol.ByteCount(1337), c.maxPacketSize())
	probe.Handler.OnAcked(probe.Frame)
	require.Equal(t, size, c.maxPacketSize())
}
