package quic

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

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
	now := time.Now()
	connID, frames, shouldSwitch := pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		&wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		false,
	)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 2)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
	pc1 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotZero(t, pc1.Data)
	require.NotEqual(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, pc1.Data)
	require.IsType(t, &wire.PathResponseFrame{}, frames[1].Frame)
	require.Equal(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, frames[1].Frame.(*wire.PathResponseFrame).Data)
	require.False(t, shouldSwitch)

	// receiving another packet for the same path doesn't trigger another PATH_CHALLENGE
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		nil,
		false,
	)
	require.Zero(t, connID)
	require.Len(t, frames, 0)
	require.False(t, shouldSwitch)

	// receiving a packet for a different path triggers another PATH_CHALLENGE
	addr2 := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000}
	connID, frames, shouldSwitch = pm.HandlePacket(addr2, now, nil, false)
	require.Equal(t, connIDs[1], connID)
	require.Len(t, frames, 1)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
	pc2 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotEqual(t, pc1.Data, pc2.Data)
	require.False(t, shouldSwitch)

	// acknowledging the PATH_CHALLENGE doesn't confirm the path
	frames[0].Handler.OnAcked(frames[0].Frame)
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		nil,
		false,
	)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)

	// receiving a PATH_RESPONSE for the second path confirms the path
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc2.Data})
	connID, frames, shouldSwitch = pm.HandlePacket(addr2, now, nil, false)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.False(t, shouldSwitch) // no non-probing packet received yet
	require.Empty(t, retiredConnIDs)

	// confirming the path doesn't remove other paths
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		nil,
		false,
	)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)

	// now receive a non-probing packet for the new path
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000},
		now,
		nil,
		true,
	)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.True(t, shouldSwitch)

	// now switch to the new path
	pm.SwitchToPath(&net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000})

	// switching to the path removes other paths
	connID, frames, shouldSwitch = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now, nil, false)
	require.Equal(t, connIDs[2], connID)
	require.NotEmpty(t, frames)
	require.NotEqual(t, frames[0].Frame.(*wire.PathChallengeFrame).Data, pc1.Data)
	require.False(t, shouldSwitch)
	require.Equal(t, []protocol.ConnectionID{connIDs[0]}, retiredConnIDs)
}

func TestPathManagerMultipleProbes(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) {},
		utils.DefaultLogger,
	)
	now := time.Now()
	// first receive a packet without a PATH_CHALLENGE
	connID, frames, shouldSwitch := pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		nil,
		false,
	)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
	require.False(t, shouldSwitch)

	// now receive a packet on the same path with a PATH_CHALLENGE
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		&wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		false,
	)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}, frames[0].Frame)
	require.False(t, shouldSwitch)

	// now receive an other packet on the same path with a PATH_RESPONSE
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		&wire.PathChallengeFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}},
		false,
	)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}}, frames[0].Frame)
	require.False(t, shouldSwitch)
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

	now := time.Now()
	connID, frames, shouldSwitch := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now, nil, true)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
	pc1 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotZero(t, pc1.Data)
	require.False(t, shouldSwitch)

	// receiving a PATH_RESPONSE for the second path confirms the path
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc1.Data})
	// we now switch to the new path, as soon as the next packet on that path is received
	connID, frames, shouldSwitch = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now, nil, false)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.True(t, shouldSwitch)
}

func TestPathManagerLimits(t *testing.T) {
	var connIDs []protocol.ConnectionID
	for range 2*maxPaths + 2 {
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

	now := time.Now()
	firstPathTime := now
	var firstPathConnID protocol.ConnectionID
	require.Greater(t, pathTimeout, maxPaths*time.Second)
	for i := range maxPaths {
		connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + i}, now, nil, true)
		require.NotEmpty(t, frames)
		require.Equal(t, connIDs[i], connID)
		if i == 0 {
			firstPathConnID = connID
		}
		now = now.Add(time.Second)
	}
	// the maximum number of paths is already being probed
	now = firstPathTime.Add(pathTimeout).Add(-time.Nanosecond)
	connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now, nil, true)
	require.Zero(t, connID)
	require.Empty(t, frames)

	// receiving another packet after the pathTimeout of the first path evicts the first path
	now = firstPathTime.Add(pathTimeout)
	connIDIndex := maxPaths
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + maxPaths}, now, nil, true)
	require.NotEmpty(t, frames)
	require.Equal(t, connIDs[connIDIndex], connID)
	require.Equal(t, []protocol.ConnectionID{firstPathConnID}, retiredConnIDs)
	connIDIndex++

	// switching to a new path frees is up all paths
	var f1 []ackhandler.Frame
	pm.SwitchToPath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000})
	for i := range maxPaths {
		connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 3000 + i}, now, nil, true)
		if i == 0 {
			f1 = frames
		}
		require.NotEmpty(t, frames)
		require.Equal(t, connIDs[connIDIndex], connID)
		connIDIndex++
	}
	// again, the maximum number of paths is already being probed
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now, nil, true)
	require.Zero(t, connID)
	require.Empty(t, frames)

	// losing the frame removes this path
	f1[0].Handler.OnLost(f1[0].Frame)

	// we can open exactly one more path
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4000}, now, nil, true)
	require.NotEmpty(t, frames)
	require.Equal(t, connIDs[connIDIndex], connID)
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4001}, now, nil, true)
	require.Zero(t, connID)
	require.Empty(t, frames)
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
