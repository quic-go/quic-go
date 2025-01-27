package quic

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// The path is established by receiving a non-probing packet.
// The first non-probing packet is received after path validation has completed.
// This is the typical scenario when the client initiates connection migration.
func TestPathManagerIntentionalMigration(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		protocol.ParseConnectionID([]byte{2, 3, 4, 5, 6, 7, 8, 9}),
		protocol.ParseConnectionID([]byte{3, 4, 5, 6, 7, 8, 9, 0}),
	}
	var retiredConnIDs []protocol.ConnectionID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		utils.DefaultLogger,
	)
	connID, f1, shouldSwitch := pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}}, false)
	require.Equal(t, connIDs[0], connID)
	require.NotNil(t, f1.Frame)
	pc1 := f1.Frame.(*wire.PathChallengeFrame)
	require.NotZero(t, pc1.Data)
	require.False(t, shouldSwitch)

	// receiving another packet for the same path doesn't trigger another PATH_CHALLENGE
	connID, f, shouldSwitch := pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}}, false)
	require.Zero(t, connID)
	require.Nil(t, f.Frame)
	require.False(t, shouldSwitch)

	// receiving a packet for a different path triggers another PATH_CHALLENGE
	addr2 := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000}
	connID, f, shouldSwitch = pm.HandlePacket(receivedPacket{remoteAddr: addr2}, false)
	require.Equal(t, connIDs[1], connID)
	require.NotNil(t, f.Frame)
	pc2 := f.Frame.(*wire.PathChallengeFrame)
	require.NotEqual(t, pc1.Data, pc2.Data)
	require.False(t, shouldSwitch)

	// acknowledging the PATH_CHALLENGE doesn't confirm the path
	f1.Handler.OnAcked(f1.Frame)
	connID, f, shouldSwitch = pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}}, false)
	require.Zero(t, connID)
	require.Nil(t, f.Frame)
	require.False(t, shouldSwitch)

	// receiving a PATH_RESPONSE for the second path confirms the path
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc2.Data})
	connID, f, shouldSwitch = pm.HandlePacket(receivedPacket{remoteAddr: addr2}, false)
	require.Zero(t, connID)
	require.Nil(t, f.Frame)
	require.False(t, shouldSwitch) // no non-probing packet received yet
	require.Empty(t, retiredConnIDs)

	// confirming the path doesn't remove other paths
	connID, f, shouldSwitch = pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}}, false)
	require.Zero(t, connID)
	require.Nil(t, f.Frame)
	require.False(t, shouldSwitch)

	// now receive a non-probing packet for the new path
	connID, f, shouldSwitch = pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000}}, true)
	require.Zero(t, connID)
	require.Nil(t, f.Frame)
	require.True(t, shouldSwitch)

	// now switch to the new path
	pm.SwitchToPath(&net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000})

	// switching to the path removes other paths
	connID, f, shouldSwitch = pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}}, false)
	require.Equal(t, connIDs[2], connID)
	require.NotNil(t, f.Frame)
	require.NotEqual(t, f.Frame.(*wire.PathChallengeFrame).Data, pc1.Data)
	require.False(t, shouldSwitch)
	require.Equal(t, []protocol.ConnectionID{connIDs[0]}, retiredConnIDs)
}

// The first packet received on the new path is already a non-probing packet.
// We still need to validate the new path, but we can then switch over immediately.
// This is the typical scenario when a NAT rebinding happens.
func TestPathManagerNATRebinding(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}
	var retiredConnIDs []protocol.ConnectionID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		utils.DefaultLogger,
	)

	connID, f, shouldSwitch := pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}}, true)
	require.Equal(t, connIDs[0], connID)
	require.NotNil(t, f.Frame)
	pc1 := f.Frame.(*wire.PathChallengeFrame)
	require.NotZero(t, pc1.Data)
	require.False(t, shouldSwitch)

	// receiving a PATH_RESPONSE for the second path confirms the path
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc1.Data})
	// we now switch to the new path, as soon as the next packet on that path is received
	connID, f, shouldSwitch = pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}}, false)
	require.Zero(t, connID)
	require.Nil(t, f.Frame)
	require.True(t, shouldSwitch)
}

func TestPathManagerLimits(t *testing.T) {
	var connIDs []protocol.ConnectionID
	for range 2*maxPaths + 1 {
		b := make([]byte, 8)
		rand.Read(b)
		connIDs = append(connIDs, protocol.ParseConnectionID(b))
	}
	var retiredConnIDs []protocol.ConnectionID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		utils.DefaultLogger,
	)

	for i := range maxPaths {
		connID, f, _ := pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + i}}, true)
		require.NotNil(t, f.Frame)
		require.Equal(t, connIDs[i], connID)
	}
	// the maximum number of paths is already being probed
	connID, f, _ := pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}}, true)
	require.Zero(t, connID)
	require.Nil(t, f.Frame)

	// switching to a new path frees is up all paths
	var f1 ackhandler.Frame
	pm.SwitchToPath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000})
	for i := range maxPaths {
		connID, f, _ := pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 3000 + i}}, true)
		if i == 0 {
			f1 = f
		}
		require.NotNil(t, f.Frame)
		require.Equal(t, connIDs[maxPaths+i], connID)
	}
	// again, the maximum number of paths is already being probed
	connID, f, _ = pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}}, true)
	require.Zero(t, connID)
	require.Nil(t, f.Frame)

	// losing the frame removes this path
	f1.Handler.OnLost(f1.Frame)

	// we can open exactly one more path
	connID, f, _ = pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4000}}, true)
	require.NotNil(t, f.Frame)
	require.Equal(t, connIDs[2*maxPaths], connID)
	connID, f, _ = pm.HandlePacket(receivedPacket{remoteAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4001}}, true)
	require.Zero(t, connID)
	require.Nil(t, f.Frame)
}

type mockAddr struct {
	str string
}

func (a *mockAddr) Network() string { return "mock" }
func (a *mockAddr) String() string  { return a.str }

func TestAddrsEqual(t *testing.T) {
	tests := []struct {
		name     string
		addr1    net.Addr
		addr2    net.Addr
		expected bool
	}{
		{
			name:     "nil addresses",
			addr1:    nil,
			addr2:    nil,
			expected: false,
		},
		{
			name:     "one nil address",
			addr1:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			addr2:    nil,
			expected: false,
		},
		{
			name:     "same IPv4 addresses",
			addr1:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			expected: true,
		},
		{
			name:     "different IPv4 addresses",
			addr1:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.IPv4(4, 3, 2, 1), Port: 1234},
			expected: false,
		},
		{
			name:     "different ports",
			addr1:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321},
			expected: false,
		},
		{
			name:     "same IPv6 addresses",
			addr1:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234},
			expected: true,
		},
		{
			name:     "different IPv6 addresses",
			addr1:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 1234},
			expected: false,
		},
		{
			name:     "non-UDP addresses with same string representation",
			addr1:    &mockAddr{str: "192.0.2.1:1234"},
			addr2:    &mockAddr{str: "192.0.2.1:1234"},
			expected: true,
		},
		{
			name:     "non-UDP addresses with different string representation",
			addr1:    &mockAddr{str: "192.0.2.1:1234"},
			addr2:    &mockAddr{str: "192.0.2.2:1234"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := addrsEqual(tt.addr1, tt.addr2)
			require.Equal(t, tt.expected, result)
		})
	}
}
