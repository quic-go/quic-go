package quic

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// connIDTracker is a connRunner that records the connection IDs it is called with.
type connIDTracker struct {
	added, removed, replaced []protocol.ConnectionID
	handlers                 []packetHandler // the packetHandlers that the connection IDs were added with
	replacedWith             []byte
}

var _ connRunner = &connIDTracker{}

func (t *connIDTracker) Add(connID protocol.ConnectionID, h packetHandler) bool {
	t.added = append(t.added, connID)
	t.handlers = append(t.handlers, h)
	return true
}

func (t *connIDTracker) Remove(connID protocol.ConnectionID) { t.removed = append(t.removed, connID) }

func (t *connIDTracker) ReplaceWithClosed(connIDs []protocol.ConnectionID, b []byte, _ time.Duration) {
	t.replaced = append(t.replaced, connIDs...)
	t.replacedWith = b
}

func (t *connIDTracker) AddResetToken(protocol.StatelessResetToken, packetHandler) {}
func (t *connIDTracker) RemoveResetToken(protocol.StatelessResetToken)             {}

func TestConnIDGeneratorIssueAndRetire(t *testing.T) {
	t.Run("with initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorIssueAndRetire(t, true)
	})
	t.Run("without initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorIssueAndRetire(t, false)
	})
}

func testConnIDGeneratorIssueAndRetire(t *testing.T, hasInitialClientDestConnID bool) {
	var tracker connIDTracker
	var queuedFrames []wire.Frame
	sr := newStatelessResetter(&StatelessResetKey{1, 2, 3, 4})
	var initialClientDestConnID protocol.ConnectionID
	if hasInitialClientDestConnID {
		initialClientDestConnID = protocol.ParseConnectionID([]byte{2, 2, 2, 2})
	}
	g := newConnIDGenerator(
		&tracker,
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		initialClientDestConnID,
		sr,
		&pathReceiver{},
		func(f wire.Frame) { queuedFrames = append(queuedFrames, f) },
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)

	require.Empty(t, tracker.added)
	require.NoError(t, g.SetMaxActiveConnIDs(4))
	require.Len(t, tracker.added, 3)
	require.Len(t, queuedFrames, 3)
	require.Empty(t, tracker.removed)
	connIDs := make(map[uint64]protocol.ConnectionID)
	// connection IDs 1, 2 and 3 were issued
	for i, f := range queuedFrames {
		ncid := f.(*wire.NewConnectionIDFrame)
		require.EqualValues(t, i+1, ncid.SequenceNumber)
		require.Equal(t, ncid.ConnectionID, tracker.added[i])
		require.Equal(t, ncid.StatelessResetToken, sr.GetStatelessResetToken(ncid.ConnectionID))
		connIDs[ncid.SequenceNumber] = ncid.ConnectionID
	}

	// completing the handshake retires the initial client destination connection ID
	tracker.added = tracker.added[:0]
	queuedFrames = queuedFrames[:0]
	now := monotime.Now()
	g.SetHandshakeComplete(now)
	require.Empty(t, tracker.added)
	require.Empty(t, queuedFrames)
	require.Empty(t, tracker.removed)
	g.RemoveRetiredConnIDs(now)
	if hasInitialClientDestConnID {
		require.Equal(t, []protocol.ConnectionID{initialClientDestConnID}, tracker.removed)
		tracker.removed = tracker.removed[:0]
	} else {
		require.Empty(t, tracker.removed)
	}

	// it's invalid to retire a connection ID that hasn't been issued yet
	err := g.Retire(4, protocol.ParseConnectionID([]byte{3, 3, 3, 3}), monotime.Now())
	require.ErrorIs(t, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation}, err)
	require.ErrorContains(t, err, "retired connection ID 4 (highest issued: 3)")
	// it's invalid to retire a connection ID in a packet that uses that connection ID
	err = g.Retire(3, connIDs[3], monotime.Now())
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "was used as the Destination Connection ID on this packet")

	// retiring a connection ID makes us issue a new one
	require.NoError(t, g.Retire(2, protocol.ParseConnectionID([]byte{3, 3, 3, 3}), monotime.Now()))
	g.RemoveRetiredConnIDs(monotime.Now())
	require.Equal(t, []protocol.ConnectionID{connIDs[2]}, tracker.removed)
	require.Len(t, queuedFrames, 1)
	require.EqualValues(t, 4, queuedFrames[0].(*wire.NewConnectionIDFrame).SequenceNumber)
	queuedFrames = queuedFrames[:0]
	tracker.removed = tracker.removed[:0]

	// duplicate retirements don't do anything
	require.NoError(t, g.Retire(2, protocol.ParseConnectionID([]byte{3, 3, 3, 3}), monotime.Now()))
	g.RemoveRetiredConnIDs(monotime.Now())
	require.Empty(t, queuedFrames)
	require.Empty(t, tracker.removed)
}

func TestConnIDGeneratorRetiring(t *testing.T) {
	initialConnID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
	var tracker connIDTracker
	g := newConnIDGenerator(
		&tracker,
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		initialConnID,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		&pathReceiver{},
		func(f wire.Frame) {},
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)
	require.NoError(t, g.SetMaxActiveConnIDs(6))
	require.Empty(t, tracker.removed)
	require.Len(t, tracker.added, 5)

	now := monotime.Now()

	retirements := map[protocol.ConnectionID]monotime.Time{}
	t1 := now.Add(time.Duration(rand.IntN(1000)) * time.Millisecond)
	retirements[initialConnID] = t1
	g.SetHandshakeComplete(t1)
	for i := range 5 {
		t2 := now.Add(time.Duration(rand.IntN(1000)) * time.Millisecond)
		require.NoError(t, g.Retire(uint64(i+1), protocol.ParseConnectionID([]byte{9, 9, 9, 9}), t2))
		retirements[tracker.added[i]] = t2

		if rand.IntN(2) == 0 {
			now = now.Add(time.Duration(rand.IntN(500)) * time.Millisecond)
			g.RemoveRetiredConnIDs(now)
			for _, r := range tracker.removed {
				require.Contains(t, retirements, r)
				require.LessOrEqual(t, retirements[r], now)
				delete(retirements, r)
			}
			tracker.removed = tracker.removed[:0]
			for _, r := range retirements {
				require.Greater(t, r, now)
			}
		}
	}
}

func TestConnIDGeneratorIsInitialClientDestConnID(t *testing.T) {
	srcConnID := protocol.ParseConnectionID([]byte{1, 1, 1, 1})
	initialClientDestConnID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})

	t.Run("server", func(t *testing.T) {
		g := newConnIDGenerator(
			&connIDTracker{},
			srcConnID,
			initialClientDestConnID,
			newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
			&pathReceiver{},
			func(f wire.Frame) {},
			&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
		)
		require.True(t, g.IsInitialClientDestConnID(initialClientDestConnID))
		require.False(t, g.IsInitialClientDestConnID(srcConnID))

		g.SetHandshakeComplete(monotime.Now())
		require.False(t, g.IsInitialClientDestConnID(initialClientDestConnID))
	})

	t.Run("client", func(t *testing.T) {
		g := newConnIDGenerator(
			&connIDTracker{},
			srcConnID,
			protocol.ConnectionID{},
			newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
			&pathReceiver{},
			func(f wire.Frame) {},
			&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
		)
		require.False(t, g.IsInitialClientDestConnID(initialClientDestConnID))
	})
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
	var initialClientDestConnID protocol.ConnectionID
	if hasInitialClientDestConnID {
		initialClientDestConnID = protocol.ParseConnectionID([]byte{2, 2, 2, 2})
	}
	var tracker connIDTracker
	g := newConnIDGenerator(
		&tracker,
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		initialClientDestConnID,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		&pathReceiver{},
		func(f wire.Frame) {},
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)

	require.NoError(t, g.SetMaxActiveConnIDs(1000))
	require.Len(t, tracker.added, protocol.MaxIssuedConnectionIDs-1)

	g.RemoveAll()
	if hasInitialClientDestConnID {
		require.Len(t, tracker.removed, protocol.MaxIssuedConnectionIDs+1)
		require.Contains(t, tracker.removed, initialClientDestConnID)
	} else {
		require.Len(t, tracker.removed, protocol.MaxIssuedConnectionIDs)
	}
	for _, id := range tracker.added {
		require.Contains(t, tracker.removed, id)
	}
	require.Contains(t, tracker.removed, protocol.ParseConnectionID([]byte{1, 1, 1, 1}))
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
	var initialClientDestConnID protocol.ConnectionID
	if hasInitialClientDestConnID {
		initialClientDestConnID = protocol.ParseConnectionID([]byte{2, 2, 2, 2})
	}
	var tracker connIDTracker
	g := newConnIDGenerator(
		&tracker,
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		initialClientDestConnID,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		&pathReceiver{},
		func(f wire.Frame) {},
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)

	require.NoError(t, g.SetMaxActiveConnIDs(1000))
	require.Len(t, tracker.added, protocol.MaxIssuedConnectionIDs-1)
	// Retire two of these connection ID.
	// This makes us issue two more connection IDs.
	require.NoError(t, g.Retire(3, protocol.ParseConnectionID([]byte{1, 1, 1, 1}), monotime.Now()))
	require.NoError(t, g.Retire(4, protocol.ParseConnectionID([]byte{1, 1, 1, 1}), monotime.Now()))
	require.Len(t, tracker.added, protocol.MaxIssuedConnectionIDs+1)

	g.ReplaceWithClosed([]byte("foobar"), time.Second)
	expected := append([]protocol.ConnectionID{protocol.ParseConnectionID([]byte{1, 1, 1, 1})}, tracker.added...)
	if hasInitialClientDestConnID {
		expected = append(expected, initialClientDestConnID)
	}
	require.ElementsMatch(t, expected, tracker.replaced)
	require.Equal(t, []byte("foobar"), tracker.replacedWith)
	require.Empty(t, tracker.removed)
}

func TestConnIDGeneratorAddConnRunner(t *testing.T) {
	initialConnID := protocol.ParseConnectionID([]byte{1, 1, 1, 1})
	clientDestConnID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})

	sr := newStatelessResetter(&StatelessResetKey{1, 2, 3, 4})
	var queuedFrames []wire.Frame

	var tracker1, tracker2 connIDTracker
	h1 := &pathReceiver{}
	g := newConnIDGenerator(
		&tracker1,
		initialConnID,
		clientDestConnID,
		sr,
		h1,
		func(f wire.Frame) { queuedFrames = append(queuedFrames, f) },
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)
	require.NoError(t, g.SetMaxActiveConnIDs(3))
	require.Len(t, tracker1.added, 2)
	h, ok := g.Handler(&tracker1)
	require.True(t, ok)
	require.Same(t, h1, h)

	// add the second runner - it should get all existing connection IDs
	h2 := &pathReceiver{}
	_, ok = g.Handler(&tracker2)
	require.False(t, ok)
	require.True(t, g.AddConnRunner(&tracker2, h2))
	h, ok = g.Handler(&tracker2)
	require.True(t, ok)
	require.Same(t, h2, h)
	require.Len(t, tracker1.added, 2) // unchanged
	require.ElementsMatch(t,
		[]protocol.ConnectionID{initialConnID, clientDestConnID, tracker1.added[0], tracker1.added[1]},
		tracker2.added,
	)
	for _, h := range tracker2.handlers {
		require.Same(t, h2, h)
	}

	// adding the same transport again doesn't do anything
	require.False(t, g.AddConnRunner(&tracker1, &pathReceiver{}))
	require.Len(t, tracker1.added, 2)
	h, ok = g.Handler(&tracker1)
	require.True(t, ok)
	require.Same(t, h1, h)

	// new connection IDs are added to both runners, with their respective handlers
	tracker1.added, tracker1.handlers = nil, nil
	tracker2.added, tracker2.handlers = nil, nil
	ncid := queuedFrames[0].(*wire.NewConnectionIDFrame)
	require.NoError(t, g.Retire(ncid.SequenceNumber, protocol.ParseConnectionID([]byte{3, 3, 3, 3}), monotime.Now()))
	require.Len(t, tracker1.added, 1)
	require.Equal(t, tracker1.added, tracker2.added)
	require.Len(t, tracker1.handlers, 1)
	require.Same(t, h1, tracker1.handlers[0])
	require.Len(t, tracker2.handlers, 1)
	require.Same(t, h2, tracker2.handlers[0])

	g.RemoveRetiredConnIDs(monotime.Now())
	require.Equal(t, []protocol.ConnectionID{ncid.ConnectionID}, tracker1.removed)
	require.Equal(t, []protocol.ConnectionID{ncid.ConnectionID}, tracker2.removed)

	tracker1.removed = nil
	tracker2.removed = nil
	g.SetHandshakeComplete(monotime.Now())
	g.RemoveRetiredConnIDs(monotime.Now())
	require.Equal(t, []protocol.ConnectionID{clientDestConnID}, tracker1.removed)
	require.Equal(t, []protocol.ConnectionID{clientDestConnID}, tracker2.removed)

	g.ReplaceWithClosed([]byte("connection closed"), time.Second)
	require.NotEmpty(t, tracker1.replaced)
	require.Equal(t, tracker1.replaced, tracker2.replaced)

	tracker1.removed = nil
	tracker2.removed = nil
	g.RemoveAll()
	require.NotEmpty(t, tracker1.removed)
	require.Equal(t, tracker1.removed, tracker2.removed)
}
