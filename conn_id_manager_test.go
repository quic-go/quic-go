package quic

import (
	"crypto/rand"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestConnIDManagerInitialConnID(t *testing.T) {
	m := newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4}), nil, nil, nil)
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4}), m.Get())
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4}), m.Get())
	m.ChangeInitialConnID(protocol.ParseConnectionID([]byte{5, 6, 7, 8}))
	require.Equal(t, protocol.ParseConnectionID([]byte{5, 6, 7, 8}), m.Get())
}

func TestConnIDManagerAddConnIDs(t *testing.T) {
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(wire.Frame) {},
	)
	f1 := &wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
	}
	f2 := &wire.NewConnectionIDFrame{
		SequenceNumber:      2,
		ConnectionID:        protocol.ParseConnectionID([]byte{0xba, 0xad, 0xf0, 0x0d}),
		StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
	}
	require.NoError(t, m.Add(f2))
	require.NoError(t, m.Add(f1)) // receiving reordered frames is fine
	require.NoError(t, m.Add(f2)) // receiving a duplicate is fine

	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4}), m.Get())
	m.updateConnectionID()
	require.Equal(t, protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}), m.Get())
	m.updateConnectionID()
	require.Equal(t, protocol.ParseConnectionID([]byte{0xba, 0xad, 0xf0, 0x0d}), m.Get())

	require.NoError(t, m.Add(f2)) // receiving a duplicate for the current connection ID is fine as well
	require.Equal(t, protocol.ParseConnectionID([]byte{0xba, 0xad, 0xf0, 0x0d}), m.Get())

	// receiving mismatching connection IDs is not fine
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      3,
		ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}), // mismatching connection ID
		StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
	}))
	require.EqualError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      3,
		ConnectionID:        protocol.ParseConnectionID([]byte{2, 3, 4, 5}), // mismatching connection ID
		StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
	}), "received conflicting connection IDs for sequence number 3")
	// receiving mismatching stateless reset tokens is not fine either
	require.EqualError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      3,
		ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		StatelessResetToken: protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0},
	}), "received conflicting stateless reset tokens for sequence number 3")
}

func TestConnIDManagerLimit(t *testing.T) {
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) {},
	)
	for i := uint8(1); i < protocol.MaxActiveConnectionIDs; i++ {
		require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      uint64(i),
			ConnectionID:        protocol.ParseConnectionID([]byte{i, i, i, i}),
			StatelessResetToken: protocol.StatelessResetToken{i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i},
		}))
	}
	require.Equal(t, &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      uint64(9999),
		ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		StatelessResetToken: protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}))
}

func TestConnIDManagerRetiringConnectionIDs(t *testing.T) {
	var frameQueue []wire.Frame
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber: 10,
		ConnectionID:   protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
	}))
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber: 13,
		ConnectionID:   protocol.ParseConnectionID([]byte{2, 3, 4, 5}),
	}))
	require.Empty(t, frameQueue)
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		RetirePriorTo:  14,
		SequenceNumber: 17,
		ConnectionID:   protocol.ParseConnectionID([]byte{3, 4, 5, 6}),
	}))
	require.Equal(t, []wire.Frame{
		&wire.RetireConnectionIDFrame{SequenceNumber: 10},
		&wire.RetireConnectionIDFrame{SequenceNumber: 13},
		&wire.RetireConnectionIDFrame{SequenceNumber: 0},
	}, frameQueue)
	require.Equal(t, protocol.ParseConnectionID([]byte{3, 4, 5, 6}), m.Get())
	frameQueue = nil

	// a reordered connection ID is immediately retired
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber: 12,
		ConnectionID:   protocol.ParseConnectionID([]byte{5, 6, 7, 8}),
	}))
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 12}}, frameQueue)
	require.Equal(t, protocol.ParseConnectionID([]byte{3, 4, 5, 6}), m.Get())
}

func TestConnIDManagerHandshakeCompletion(t *testing.T) {
	var frameQueue []wire.Frame
	var addedTokens, removedTokens []protocol.StatelessResetToken
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(token protocol.StatelessResetToken) { addedTokens = append(addedTokens, token) },
		func(token protocol.StatelessResetToken) { removedTokens = append(removedTokens, token) },
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)
	m.SetStatelessResetToken(protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	require.Equal(t, []protocol.StatelessResetToken{{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}}, addedTokens)
	require.Empty(t, removedTokens)

	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}))
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4}), m.Get())
	m.SetHandshakeComplete()
	require.Equal(t, protocol.ParseConnectionID([]byte{4, 3, 2, 1}), m.Get())
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 0}}, frameQueue)
	require.Equal(t, []protocol.StatelessResetToken{{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}}, removedTokens)
}

func TestConnIDManagerConnIDRotation(t *testing.T) {
	var frameQueue []wire.Frame
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)
	// the first connection ID is used as soon as the handshake is complete
	m.SetHandshakeComplete()
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}))
	require.Equal(t, protocol.ParseConnectionID([]byte{4, 3, 2, 1}), m.Get())
	frameQueue = nil

	// Note that we're missing the connection ID with sequence number 2.
	// It will be received later.
	var queuedConnIDs []protocol.ConnectionID
	for i := 0; i < protocol.MaxActiveConnectionIDs-1; i++ {
		b := make([]byte, 4)
		rand.Read(b)
		connID := protocol.ParseConnectionID(b)
		queuedConnIDs = append(queuedConnIDs, connID)
		require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      uint64(3 + i),
			ConnectionID:        connID,
			StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		}))
	}

	var counter int
	for {
		require.Empty(t, frameQueue)
		m.SentPacket()
		counter++
		if m.Get() != protocol.ParseConnectionID([]byte{4, 3, 2, 1}) {
			require.Equal(t, queuedConnIDs[0], m.Get())
			require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 1}}, frameQueue)
			break
		}
	}
	require.GreaterOrEqual(t, counter, protocol.PacketsPerConnectionID/2)
	require.LessOrEqual(t, counter, protocol.PacketsPerConnectionID*3/2)
	frameQueue = nil

	// now receive connection ID 2
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber: 2,
		ConnectionID:   protocol.ParseConnectionID([]byte{2, 3, 4, 5}),
	}))
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 2}}, frameQueue)
}

func TestConnIDManagerPathMigration(t *testing.T) {
	var frameQueue []wire.Frame
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)

	// no connection ID available yet
	_, ok := m.GetConnIDForPath(1)
	require.False(t, ok)

	// add a connection ID
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}))
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      2,
		ConnectionID:        protocol.ParseConnectionID([]byte{5, 4, 3, 2}),
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}))
	connID, ok := m.GetConnIDForPath(1)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{4, 3, 2, 1}), connID)
	connID, ok = m.GetConnIDForPath(2)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{5, 4, 3, 2}), connID)
	// asking for the connection for path 1 again returns the same connection ID
	connID, ok = m.GetConnIDForPath(1)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{4, 3, 2, 1}), connID)

	// if the connection ID is retired, the path will use another connection ID
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      3,
		RetirePriorTo:       2,
		ConnectionID:        protocol.ParseConnectionID([]byte{6, 5, 4, 3}),
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}))
	require.Len(t, frameQueue, 2)
	frameQueue = nil

	require.Equal(t, protocol.ParseConnectionID([]byte{6, 5, 4, 3}), m.Get())
	// the connection ID is not used for new paths
	_, ok = m.GetConnIDForPath(3)
	require.False(t, ok)

	// Manually retiring the connection ID does nothing.
	// Path 1 doesn't have a connection ID anymore.
	m.RetireConnIDForPath(1)
	require.Empty(t, frameQueue)
	_, ok = m.GetConnIDForPath(1)
	require.False(t, ok)

	// only after a new connection ID is added, it will be used for path 1
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      4,
		ConnectionID:        protocol.ParseConnectionID([]byte{7, 6, 5, 4}),
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}))
	connID, ok = m.GetConnIDForPath(1)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{7, 6, 5, 4}), connID)

	// a RETIRE_CONNECTION_ID frame for path 1 is queued when retiring the connection ID
	m.RetireConnIDForPath(1)
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 4}}, frameQueue)
}

func TestConnIDManagerZeroLengthConnectionID(t *testing.T) {
	m := newConnIDManager(
		protocol.ConnectionID{},
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) {},
	)
	require.Equal(t, protocol.ConnectionID{}, m.Get())
	for i := 0; i < 5*protocol.PacketsPerConnectionID; i++ {
		m.SentPacket()
		require.Equal(t, protocol.ConnectionID{}, m.Get())
	}

	// for path probing, we don't need to change the connection ID
	for id := pathID(1); id < 10; id++ {
		connID, ok := m.GetConnIDForPath(id)
		require.True(t, ok)
		require.Equal(t, protocol.ConnectionID{}, connID)
	}
	// retiring a connection ID for a path is also a no-op
	for id := pathID(1); id < 20; id++ {
		m.RetireConnIDForPath(id)
	}

	require.ErrorIs(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        protocol.ConnectionID{},
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}), &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
}

func TestConnIDManagerClose(t *testing.T) {
	var addedTokens, removedTokens []protocol.StatelessResetToken
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(token protocol.StatelessResetToken) { addedTokens = append(addedTokens, token) },
		func(token protocol.StatelessResetToken) { removedTokens = append(removedTokens, token) },
		func(f wire.Frame) {},
	)
	m.SetStatelessResetToken(protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	require.Equal(t, []protocol.StatelessResetToken{{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}}, addedTokens)
	require.Empty(t, removedTokens)
	m.Close()
	require.Equal(t, []protocol.StatelessResetToken{{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}}, removedTokens)

	require.Panics(t, func() { m.Get() })
	require.Panics(t, func() { m.SetStatelessResetToken(protocol.StatelessResetToken{}) })
}
