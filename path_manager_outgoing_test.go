package quic

import (
	"context"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestPathManagerOutgoing(t *testing.T) {
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
	p := pm.NewPath(tr1, func() { enabled = true })
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
	switchToTransport, ok := pm.ShouldSwitchPath()
	require.True(t, ok)
	require.Equal(t, tr1, switchToTransport)
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
	p1 := pm.NewPath(&Transport{}, func() {})
	errChan := make(chan error, 1)
	go func() { errChan <- p1.Probe(context.Background()) }()

	// wait for the path to be queued for probing
	time.Sleep(scaleDuration(5 * time.Millisecond))

	require.NoError(t, p1.Close())
	_, _, _, ok := pm.NextPathToProbe()
	require.False(t, ok)

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, ErrPathAbandoned)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.Empty(t, retiredPaths)

	p2 := pm.NewPath(&Transport{}, func() {})
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
	require.ErrorIs(t, p2.Switch(), ErrPathAbandoned)
}
