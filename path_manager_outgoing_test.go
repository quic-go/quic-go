package quic

import (
	"context"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestPathManagerOutgoingPathProbing(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}
	pm := newPathManagerOutgoing(
		func(id pathID) (protocol.ConnectionID, bool) {
			connID := connIDs[0]
			connIDs = connIDs[1:]
			return connID, true
		},
		func(id pathID) { t.Fatal("didn't expect any connection ID to be retired") },
		func() {},
	)

	_, _, _, ok := pm.NextPathToProbe()
	require.False(t, ok)

	tr1 := &Transport{}
	var enabled bool
	p := pm.NewPath(tr1, time.Second, func() { enabled = true })
	require.ErrorIs(t, p.Switch(), ErrPathNotValidated)

	errChan := make(chan error, 1)
	go func() { errChan <- p.Probe(context.Background()) }()

	// wait for the path to be queued for probing
	time.Sleep(scaleDuration(5 * time.Millisecond))

	require.False(t, enabled)
	connID, f, tr, ok := pm.NextPathToProbe()
	require.True(t, ok)
	require.Equal(t, tr1, tr)
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}), connID)
	require.IsType(t, &wire.PathChallengeFrame{}, f.Frame)
	pc := f.Frame.(*wire.PathChallengeFrame)
	require.True(t, enabled)

	_, _, _, ok = pm.NextPathToProbe()
	require.False(t, ok)

	select {
	case <-errChan:
		t.Fatal("should still be probing")
	default:
	}

	// acking the frame doesn't complete path validation...
	f.Handler.OnAcked(f.Frame)
	select {
	case <-errChan:
		t.Fatal("should still be probing")
	default:
	}

	require.ErrorIs(t, p.Switch(), ErrPathNotValidated)
	_, ok = pm.ShouldSwitchPath()
	require.False(t, ok)

	// ... neither does receiving a random PATH_RESPONSE...
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: [8]byte{'f', 'o', 'o', 'f', 'o', 'o'}})
	f.Handler.OnAcked(f.Frame) // doesn't do anything
	f.Handler.OnLost(f.Frame)  // doesn't do anything
	select {
	case <-errChan:
		t.Fatal("should still be probing")
	default:
	}

	// ... only receiving the corresponding PATH_RESPONSE does
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc.Data})
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// receiving it multiple times is ok
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc.Data})

	// now switch to the other path
	_, ok = pm.ShouldSwitchPath()
	require.False(t, ok)
	require.NoError(t, p.Switch())
	// the active path can't be closed
	require.EqualError(t, p.Close(), "cannot close active path")
	switchToTransport, ok := pm.ShouldSwitchPath()
	require.True(t, ok)
	require.Equal(t, tr1, switchToTransport)
}

func TestPathManagerOutgoingRetransmissions(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		protocol.ParseConnectionID([]byte{2, 3, 4, 5, 6, 7, 8, 9}),
	}
	var retiredConnIDs []protocol.ConnectionID
	scheduledSending := make(chan struct{}, 20)
	pm := newPathManagerOutgoing(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		func() { scheduledSending <- struct{}{} },
	)

	_, _, _, ok := pm.NextPathToProbe()
	require.False(t, ok)

	tr1 := &Transport{}
	initialRTT := scaleDuration(2 * time.Millisecond)
	p := pm.NewPath(tr1, initialRTT, func() {})

	pathChallengeChan := make(chan [8]byte)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-scheduledSending:
			case <-done:
				return
			}
			_, f, _, ok := pm.NextPathToProbe()
			if !ok {
				// should never happen
				pathChallengeChan <- [8]byte{}
				continue
			}
			pathChallengeChan <- f.Frame.(*wire.PathChallengeFrame).Data
		}
	}()

	errChan := make(chan error, 1)
	go func() { errChan <- p.Probe(context.Background()) }()

	start := time.Now()
	var pathChallenges [][8]byte
	for range 4 {
		select {
		case err := <-errChan:
			require.NoError(t, err)
		case pc := <-pathChallengeChan:
			pathChallenges = append(pathChallenges, pc)
		case <-time.After(scaleDuration(time.Second)):
			t.Fatal("timeout")
		}
	}
	took := time.Since(start)

	require.NotContains(t, pathChallenges, [8]byte{})
	require.NotEqual(t, pathChallenges[0], pathChallenges[1])
	require.NotEqual(t, pathChallenges[0], pathChallenges[2])
	require.NotEqual(t, pathChallenges[0], pathChallenges[3])
	require.NotEqual(t, pathChallenges[1], pathChallenges[2])
	require.NotEqual(t, pathChallenges[2], pathChallenges[3])

	require.Greater(t, took, initialRTT*(1+2+4+8))
	require.Less(t, took, initialRTT*(1+2+4+8)*3/2)

	// receiving a PATH_RESPONSE for any of the PATH_CHALLENGES completes path validation
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pathChallenges[2]})

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// It is valid to probe again
	pathChallenges = pathChallenges[:0]
	ctx, cancel := context.WithCancel(context.Background())
	go func() { errChan <- p.Probe(ctx) }()

	for range 2 {
		select {
		case err := <-errChan:
			require.NoError(t, err)
		case pc := <-pathChallengeChan:
			pathChallenges = append(pathChallenges, pc)
		case <-time.After(scaleDuration(time.Second)):
			t.Fatal("timeout")
		}
	}
	// this time, don't receive a PATH_RESPONSE
	cancel()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestPathManagerOutgoingAbandonPath(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}
	var retiredPaths []pathID
	pm := newPathManagerOutgoing(
		func(id pathID) (protocol.ConnectionID, bool) {
			connID := connIDs[0]
			connIDs = connIDs[1:]
			return connID, true
		},
		func(id pathID) { retiredPaths = append(retiredPaths, id) },
		func() {},
	)

	// path abandoned before the PATH_CHALLENGE is sent out
	p1 := pm.NewPath(&Transport{}, time.Second, func() {})
	errChan := make(chan error, 1)
	go func() { errChan <- p1.Probe(context.Background()) }()

	// wait for the path to be queued for probing
	time.Sleep(scaleDuration(5 * time.Millisecond))

	require.NoError(t, p1.Close())
	// closing the path multiple times is ok
	require.NoError(t, p1.Close())
	require.NoError(t, p1.Close())
	_, _, _, ok := pm.NextPathToProbe()
	require.False(t, ok)

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, ErrPathClosed)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.Empty(t, retiredPaths)

	p2 := pm.NewPath(&Transport{}, time.Second, func() {})
	go func() { errChan <- p2.Probe(context.Background()) }()

	// wait for the path to be queued for probing
	time.Sleep(scaleDuration(5 * time.Millisecond))
	connID, f, _, ok := pm.NextPathToProbe()
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}), connID)

	require.NoError(t, p2.Close())
	require.Equal(t, []pathID{p2.id}, retiredPaths)
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: f.Frame.(*wire.PathChallengeFrame).Data})
	_, _, _, ok = pm.NextPathToProbe()
	require.False(t, ok)
	// it's not possible to switch to an abandoned path
	require.ErrorIs(t, p2.Switch(), ErrPathClosed)
}
