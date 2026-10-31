package quic

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestPathValidationExpiresAfterInactivityServer(t *testing.T) {
	pm := newPathManager(
		func(pathID) (protocol.ConnectionID, bool) {
			return protocol.ParseConnectionID([]byte{1, 2, 3, 4}), true
		},
		func(pathID) { t.Fatal("expiration must not retire a connection ID") },
		utils.DefaultLogger,
	)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	now := monotime.Now()
	pm.GetOrCreatePath(addr, now)
	_, frames, _ := pm.HandlePacket(addr, now, nil, false)
	challenge := frames[0].Frame.(*wire.PathChallengeFrame)
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: challenge.Data}, monotime.Now())
	_, _, shouldSwitch := pm.HandlePacket(addr, now.Add(30*time.Second), nil, true)
	require.False(t, shouldSwitch, "a path idle for 30 seconds must be validated again before migration")
}

func TestPathValidationExpiresAfterInactivityClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pm := newPathManagerOutgoing(
			func(pathID) (protocol.ConnectionID, bool) {
				return protocol.ParseConnectionID([]byte{1, 2, 3, 4}), true
			},
			func(pathID) { t.Fatal("expiration must not retire a connection ID") },
			func() {},
		)
		p := pm.NewPath(&Transport{}, time.Second, func(id pathID) pathID { return id })
		done := make(chan error, 1)
		go func() { done <- p.Probe(context.Background()) }()
		synctest.Wait()
		_, f, _, ok := pm.NextPathToProbe()
		require.True(t, ok)
		pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: f.Frame.(*wire.PathChallengeFrame).Data}, monotime.Now())
		synctest.Wait()
		require.NoError(t, <-done)
		time.Sleep(30 * time.Second)
		require.ErrorIs(t, p.Switch(), ErrPathNotValidated, "a path idle for 30 seconds must be probed again")
	})
}

func TestPathValidationServerBoundary(t *testing.T) {
	for _, elapsed := range []time.Duration{30*time.Second - time.Nanosecond, 30 * time.Second, 30*time.Second + time.Nanosecond} {
		t.Run(elapsed.String(), func(t *testing.T) {
			connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
			pm := newPathManager(func(pathID) (protocol.ConnectionID, bool) { return connID, true },
				func(pathID) { t.Fatal("unexpected CID retirement") }, utils.DefaultLogger)
			addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
			now := monotime.Now()
			pm.GetOrCreatePath(addr, now)
			_, frames, _ := pm.HandlePacket(addr, now, nil, false)
			old := frames[0].Frame.(*wire.PathChallengeFrame).Data
			pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: old}, now)
			later := now.Add(elapsed)
			pm.GetOrCreatePath(addr, later)
			// A response in the arriving packet is processed before HandlePacket.
			pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: old}, later)
			cid, frames, switched := pm.HandlePacket(addr, later, &wire.PathChallengeFrame{Data: [8]byte{9}}, true)
			require.Equal(t, connID, cid)
			require.Equal(t, elapsed < 30*time.Second, switched)
			if elapsed < 30*time.Second {
				require.Len(t, frames, 1)
				return
			}
			require.Len(t, frames, 2)
			fresh := frames[0].Frame.(*wire.PathChallengeFrame).Data
			require.NotEqual(t, old, fresh)
			require.Equal(t, [8]byte{9}, frames[1].Frame.(*wire.PathResponseFrame).Data)
			pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: old}, later)
			require.False(t, pm.paths[0].validated)
			pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: fresh}, later.Add(time.Millisecond))
			_, _, switched = pm.HandlePacket(addr, later.Add(time.Millisecond), nil, false)
			require.True(t, switched)
		})
	}
}

func TestPathValidationServerReceiveRefresh(t *testing.T) {
	pm := newPathManager(func(pathID) (protocol.ConnectionID, bool) { return protocol.ParseConnectionID([]byte{1}), true },
		func(pathID) { t.Fatal("unexpected CID retirement") }, utils.DefaultLogger)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	now := monotime.Now()
	pm.GetOrCreatePath(addr, now)
	_, frames, _ := pm.HandlePacket(addr, now, nil, false)
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: frames[0].Frame.(*wire.PathChallengeFrame).Data}, now)
	for _, delta := range []time.Duration{20 * time.Second, 49 * time.Second} {
		pm.GetOrCreatePath(addr, now.Add(delta))
		_, frames, switched := pm.HandlePacket(addr, now.Add(delta), nil, false)
		require.Empty(t, frames)
		require.False(t, switched)
		require.True(t, pm.paths[0].validated)
	}
}

func TestPathValidationClientBoundaryAndReprobe(t *testing.T) {
	for _, elapsed := range []time.Duration{30*time.Second - time.Nanosecond, 30 * time.Second, 30*time.Second + time.Nanosecond} {
		t.Run(elapsed.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var retired []pathID
				pm := newPathManagerOutgoing(func(pathID) (protocol.ConnectionID, bool) { return protocol.ParseConnectionID([]byte{1}), true },
					func(id pathID) { retired = append(retired, id) }, func() {})
				p := pm.NewPath(&Transport{}, time.Second, func(id pathID) pathID { return id })
				done := make(chan error, 1)
				go func() { done <- p.Probe(context.Background()) }()
				synctest.Wait()
				_, f, _, ok := pm.NextPathToProbe()
				require.True(t, ok)
				old := f.Frame.(*wire.PathChallengeFrame).Data
				pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: old}, monotime.Now())
				synctest.Wait()
				require.NoError(t, <-done)
				time.Sleep(elapsed)
				if elapsed < 30*time.Second {
					require.NoError(t, p.Switch())
					return
				}
				require.ErrorIs(t, p.Switch(), ErrPathNotValidated)
				_, _, switched := pm.ShouldSwitchPath()
				require.False(t, switched)
				require.Empty(t, retired)
				// Receiving traffic alone cannot restore an expired validation.
				pm.HandlePacket(p.id, monotime.Now())
				require.ErrorIs(t, p.Switch(), ErrPathNotValidated)
				go func() { done <- p.Probe(context.Background()) }()
				synctest.Wait()
				_, f, _, ok = pm.NextPathToProbe()
				require.True(t, ok)
				fresh := f.Frame.(*wire.PathChallengeFrame).Data
				require.NotEqual(t, old, fresh)
				pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: old}, monotime.Now())
				require.ErrorIs(t, p.Switch(), ErrPathNotValidated)
				pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: fresh}, monotime.Now())
				synctest.Wait()
				require.NoError(t, <-done)
				require.NoError(t, p.Switch())
				_, _, switched = pm.ShouldSwitchPath()
				require.True(t, switched)
				require.EqualError(t, p.Close(), "cannot close active path")
			})
		})
	}
}

func TestPathValidationSwitchLinearizesAtRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pm := newPathManagerOutgoing(nil, func(pathID) { t.Fatal("unexpected CID retirement") }, func() {})
		p := pm.NewPath(&Transport{}, time.Second, func(id pathID) pathID { return id })
		state := pm.addPath(p, p.enablePath)
		state.isValidated = true
		state.lastPacketTime = monotime.Now()
		require.NoError(t, p.Switch())
		time.Sleep(30 * time.Second)
		// A successful Switch is committed at the request, not silently canceled later.
		id, _, switched := pm.ShouldSwitchPath()
		require.True(t, switched)
		require.Equal(t, p.id, id)
		require.ErrorIs(t, p.Switch(), ErrPathNotValidated)
	})
}

func TestConnectionPathValidationReceiveIdentity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(ctrl)
		tc := newClientTestConnection(t, ctrl, nil, false, connectionOptUnpacker(unpacker), connectionOptHandshakeConfirmed())
		pm := newPathManagerOutgoing(nil, func(pathID) {}, func() {})
		tc.conn.pathManagerOutgoing.Store(pm)
		now := monotime.Now()
		newPath := func(source pathID) *Path {
			p := pm.NewPath(&Transport{}, time.Second, func(pathID) pathID { return source })
			state := pm.addPath(p, p.enablePath)
			state.receivePath = source
			state.isValidated = true
			state.lastPacketTime = now
			return p
		}
		a, b, alias := newPath(0), newPath(42), newPath(0)
		// The application requests B, but the run loop is still receiving on A.
		require.NoError(t, b.Switch())
		var pn protocol.PacketNumber
		receive := func(source *pathReceiver, at monotime.Time, duplicate, decryptFail bool) {
			t.Helper()
			if !duplicate {
				pn++
			}
			packet := getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, pn, nil)
			packet.rcvTime = at
			var unpackErr error
			if decryptFail {
				unpackErr = handshake.ErrDecryptionFailed
			}
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(pn, protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{0}, unpackErr)
			require.True(t, tc.conn.receivedPackets.Push(packet, source))
			processed, err := tc.conn.handlePackets()
			require.NoError(t, err)
			require.Equal(t, !duplicate && !decryptFail, processed)
		}
		time.Sleep(29 * time.Second)
		receive(&tc.conn.pathReceiver, monotime.Now(), false, false)
		require.Equal(t, monotime.Now(), pm.paths[a.id].lastPacketTime)
		require.Equal(t, monotime.Now(), pm.paths[alias.id].lastPacketTime)
		require.Equal(t, now, pm.paths[b.id].lastPacketTime)
		time.Sleep(time.Second)
		// Replayed and unauthenticated traffic must not refresh A either.
		receive(&tc.conn.pathReceiver, monotime.Now(), true, false)
		receive(&tc.conn.pathReceiver, monotime.Now(), false, true)
		require.Equal(t, now.Add(29*time.Second), pm.paths[a.id].lastPacketTime)
		_, _, switched := pm.ShouldSwitchPath()
		require.True(t, switched) // the earlier successful request remains committed
		require.ErrorIs(t, b.Switch(), ErrPathNotValidated)
		require.NoError(t, a.Switch())
		// A delayed packet for A must retain its identity after SwapActive(B).
		packet := getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, pn+1, nil)
		packet.rcvTime = now.Add(28 * time.Second)
		require.True(t, tc.conn.receivedPackets.Push(packet, &tc.conn.pathReceiver))
		tc.conn.receivedPackets.SwapActive(&pathReceiver{id: 42})
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(pn+1, protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{0}, nil)
		processed, err := tc.conn.handlePackets()
		require.NoError(t, err)
		require.True(t, processed)
		require.Equal(t, now.Add(29*time.Second), pm.paths[a.id].lastPacketTime)
		require.Equal(t, now, pm.paths[b.id].lastPacketTime)
	})
}

func TestPathValidationClientReceiveBeforeSwitch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pm := newPathManagerOutgoing(nil, func(pathID) { t.Fatal("unexpected CID retirement") }, func() {})
		p := pm.NewPath(&Transport{}, time.Second, func(id pathID) pathID { return id })
		state := pm.addPath(p, p.enablePath)
		state.receivePath = p.id
		state.isValidated = true
		state.lastPacketTime = monotime.Now()
		time.Sleep(30 * time.Second)
		// The first packet after inactivity must not revive the previous validation.
		// In particular, expiration has to happen before recording this new receive time.
		pm.HandlePacket(p.id, monotime.Now())
		require.ErrorIs(t, p.Switch(), ErrPathNotValidated)
		require.Equal(t, monotime.Now(), state.lastPacketTime)
		require.False(t, state.isValidated)
	})
}
