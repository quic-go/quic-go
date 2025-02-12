package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestConnIDGeneratorIssueAndRetire(t *testing.T) {
	t.Run("with initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorIssueAndRetire(t, true)
	})
	t.Run("without initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorIssueAndRetire(t, false)
	})
}

func testConnIDGeneratorIssueAndRetire(t *testing.T, hasInitialClientDestConnID bool) {
	var (
		added   []protocol.ConnectionID
		retired []protocol.ConnectionID
	)
	var queuedFrames []wire.Frame
	sr := newStatelessResetter(&StatelessResetKey{1, 2, 3, 4})
	var initialClientDestConnID *protocol.ConnectionID
	if hasInitialClientDestConnID {
		connID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
		initialClientDestConnID = &connID
	}
	g := newConnIDGenerator(
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		initialClientDestConnID,
		func(c protocol.ConnectionID) { added = append(added, c) },
		sr,
		func(c protocol.ConnectionID) { t.Fatal("didn't expect conn ID removals") },
		func(c protocol.ConnectionID) { retired = append(retired, c) },
		func([]protocol.ConnectionID, []byte) {},
		func(f wire.Frame) { queuedFrames = append(queuedFrames, f) },
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)

	require.Empty(t, added)
	require.NoError(t, g.SetMaxActiveConnIDs(4))
	require.Len(t, added, 3)
	require.Len(t, queuedFrames, 3)
	require.Empty(t, retired)
	connIDs := make(map[uint64]protocol.ConnectionID)
	// connection IDs 1, 2 and 3 were issued
	for i, f := range queuedFrames {
		ncid := f.(*wire.NewConnectionIDFrame)
		require.EqualValues(t, i+1, ncid.SequenceNumber)
		require.Equal(t, ncid.ConnectionID, added[i])
		require.Equal(t, ncid.StatelessResetToken, sr.GetStatelessResetToken(ncid.ConnectionID))
		connIDs[ncid.SequenceNumber] = ncid.ConnectionID
	}

	// completing the handshake retires the initial client destination connection ID
	added = added[:0]
	queuedFrames = queuedFrames[:0]
	g.SetHandshakeComplete()
	require.Empty(t, added)
	require.Empty(t, queuedFrames)
	if hasInitialClientDestConnID {
		require.Equal(t, []protocol.ConnectionID{*initialClientDestConnID}, retired)
		retired = retired[:0]
	} else {
		require.Empty(t, retired)
	}

	// it's invalid to retire a connection ID that hasn't been issued yet
	err := g.Retire(4, protocol.ParseConnectionID([]byte{3, 3, 3, 3}))
	require.ErrorIs(t, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation}, err)
	require.ErrorContains(t, err, "retired connection ID 4 (highest issued: 3)")
	// it's invalid to retire a connection ID in a packet that uses that connection ID
	err = g.Retire(3, connIDs[3])
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "was used as the Destination Connection ID on this packet")

	// retiring a connection ID makes us issue a new one
	require.NoError(t, g.Retire(2, protocol.ParseConnectionID([]byte{3, 3, 3, 3})))
	require.Equal(t, []protocol.ConnectionID{connIDs[2]}, retired)
	require.Len(t, queuedFrames, 1)
	require.EqualValues(t, 4, queuedFrames[0].(*wire.NewConnectionIDFrame).SequenceNumber)
	queuedFrames = queuedFrames[:0]
	retired = retired[:0]

	// duplicate retirements don't do anything
	require.NoError(t, g.Retire(2, protocol.ParseConnectionID([]byte{3, 3, 3, 3})))
	require.Empty(t, queuedFrames)
	require.Empty(t, retired)
}

func TestConnIDGeneratorRemoveAll(t *testing.T) {
	t.Run("with initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorRemoveAll(t, true)
	})
	t.Run("without initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorRemoveAll(t, false)
	})
}

func testConnIDGeneratorRemoveAll(t *testing.T, hasInitialClientDestConnID bool) {
	var initialClientDestConnID *protocol.ConnectionID
	if hasInitialClientDestConnID {
		connID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
		initialClientDestConnID = &connID
	}
	var (
		added   []protocol.ConnectionID
		removed []protocol.ConnectionID
	)
	g := newConnIDGenerator(
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		initialClientDestConnID,
		func(c protocol.ConnectionID) { added = append(added, c) },
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		func(c protocol.ConnectionID) { removed = append(removed, c) },
		func(c protocol.ConnectionID) { t.Fatal("didn't expect conn ID retirements") },
		func([]protocol.ConnectionID, []byte) {},
		func(f wire.Frame) {},
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)

	require.NoError(t, g.SetMaxActiveConnIDs(1000))
	require.Len(t, added, protocol.MaxIssuedConnectionIDs-1)

	g.RemoveAll()
	if hasInitialClientDestConnID {
		require.Len(t, removed, protocol.MaxIssuedConnectionIDs+1)
		require.Contains(t, removed, *initialClientDestConnID)
	} else {
		require.Len(t, removed, protocol.MaxIssuedConnectionIDs)
	}
	for _, id := range added {
		require.Contains(t, removed, id)
	}
	require.Contains(t, removed, protocol.ParseConnectionID([]byte{1, 1, 1, 1}))
}

func TestConnIDGeneratorReplaceWithClosed(t *testing.T) {
	t.Run("with initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorReplaceWithClosed(t, true)
	})
	t.Run("without initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorReplaceWithClosed(t, false)
	})
}

func testConnIDGeneratorReplaceWithClosed(t *testing.T, hasInitialClientDestConnID bool) {
	var initialClientDestConnID *protocol.ConnectionID
	if hasInitialClientDestConnID {
		connID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
		initialClientDestConnID = &connID
	}
	var (
		added        []protocol.ConnectionID
		replaced     []protocol.ConnectionID
		replacedWith []byte
	)
	g := newConnIDGenerator(
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		initialClientDestConnID,
		func(c protocol.ConnectionID) { added = append(added, c) },
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		func(c protocol.ConnectionID) { t.Fatal("didn't expect conn ID removals") },
		func(c protocol.ConnectionID) { t.Fatal("didn't expect conn ID retirements") },
		func(connIDs []protocol.ConnectionID, b []byte) {
			replaced = connIDs
			replacedWith = b
		},
		func(f wire.Frame) {},
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)

	require.NoError(t, g.SetMaxActiveConnIDs(1000))
	require.Len(t, added, protocol.MaxIssuedConnectionIDs-1)

	g.ReplaceWithClosed([]byte("foobar"))
	if hasInitialClientDestConnID {
		require.Len(t, replaced, protocol.MaxIssuedConnectionIDs+1)
		require.Contains(t, replaced, *initialClientDestConnID)
	} else {
		require.Len(t, replaced, protocol.MaxIssuedConnectionIDs)
	}
	for _, id := range added {
		require.Contains(t, replaced, id)
	}
	require.Contains(t, replaced, protocol.ParseConnectionID([]byte{1, 1, 1, 1}))
	require.Equal(t, []byte("foobar"), replacedWith)
}
