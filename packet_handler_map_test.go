package quic

import (
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

func TestPacketHandlerMapAddAndRemove(t *testing.T) {
	m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	h := &mockPacketHandler{}
	require.True(t, m.Add(connID, h))
	got, ok := m.Get(connID)
	require.True(t, ok)
	require.Equal(t, h, got)

	// cannot add the same handler twice
	require.False(t, m.Add(connID, h))
	got, ok = m.Get(connID)
	require.True(t, ok)
	require.Equal(t, h, got)

	// remove the handler
	m.Remove(connID)
	got, ok = m.Get(connID)
	require.False(t, ok)
	require.Nil(t, got)
}

func TestPacketHandlerMapAddWithClientChosenConnID(t *testing.T) {
	m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
	h := &mockPacketHandler{}

	connID1 := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	connID2 := protocol.ParseConnectionID([]byte{4, 3, 2, 1})
	require.True(t, m.AddWithConnID(connID1, connID2, h))
	// collision of the connection ID, this handler should not be added
	require.False(t, m.AddWithConnID(connID1, protocol.ParseConnectionID([]byte{1, 2, 3}), nil))

	got, ok := m.Get(connID1)
	require.True(t, ok)
	require.Equal(t, h, got)
	got, ok = m.Get(connID2)
	require.True(t, ok)
	require.Equal(t, h, got)
}

func TestPacketHandlerMapRetire(t *testing.T) {
	m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
	dur := scaleDuration(10 * time.Millisecond)
	m.deleteRetiredConnsAfter = dur
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	h := &mockPacketHandler{}
	require.True(t, m.Add(connID, h))
	m.Retire(connID)

	// immediately after retiring, the handler should still be there
	got, ok := m.Get(connID)
	require.True(t, ok)
	require.Equal(t, h, got)

	// after the timeout, the handler should be removed
	time.Sleep(dur)
	require.Eventually(t, func() bool {
		_, ok := m.Get(connID)
		return !ok
	}, dur, dur/10)
}

func TestPacketHandlerMapAddGetRemoveResetTokens(t *testing.T) {
	m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
	token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}
	handler := &mockPacketHandler{}
	m.AddResetToken(token, handler)
	h, ok := m.GetByResetToken(token)
	require.True(t, ok)
	require.Equal(t, handler, h)
	m.RemoveResetToken(token)
	_, ok = m.GetByResetToken(token)
	require.False(t, ok)
}

func TestPacketHandlerMapGenerateStatelessResetToken(t *testing.T) {
	t.Run("no key", func(t *testing.T) {
		m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
		b := make([]byte, 8)
		rand.Read(b)
		connID := protocol.ParseConnectionID(b)
		tokens := make(map[protocol.StatelessResetToken]struct{})
		for i := 0; i < 100; i++ {
			token := m.GetStatelessResetToken(connID)
			require.NotZero(t, token)
			if _, ok := tokens[token]; ok {
				t.Fatalf("token %s already exists", token)
			}
			tokens[token] = struct{}{}
		}
	})

	t.Run("with key", func(t *testing.T) {
		var key StatelessResetKey
		rand.Read(key[:])
		m := newPacketHandlerMap(&key, nil, utils.DefaultLogger)
		b := make([]byte, 8)
		rand.Read(b)
		connID := protocol.ParseConnectionID(b)
		token := m.GetStatelessResetToken(connID)
		require.NotZero(t, token)
		require.Equal(t, token, m.GetStatelessResetToken(connID))
		// generate a new connection ID
		rand.Read(b)
		connID2 := protocol.ParseConnectionID(b)
		require.NotEqual(t, token, m.GetStatelessResetToken(connID2))
	})
}

func TestPacketHandlerMapReplaceWithLocalClosed(t *testing.T) {
	var closePackets []closePacket
	m := newPacketHandlerMap(nil, func(p closePacket) { closePackets = append(closePackets, p) }, utils.DefaultLogger)
	dur := scaleDuration(10 * time.Millisecond)
	m.deleteRetiredConnsAfter = dur

	handler := &mockPacketHandler{}
	connID := protocol.ParseConnectionID([]byte{4, 3, 2, 1})
	require.True(t, m.Add(connID, handler))
	m.ReplaceWithClosed([]protocol.ConnectionID{connID}, []byte("foobar"))
	h, ok := m.Get(connID)
	require.True(t, ok)
	require.NotEqual(t, handler, h)
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
	h.handlePacket(receivedPacket{remoteAddr: addr})
	require.Len(t, closePackets, 1)
	require.Equal(t, addr, closePackets[0].addr)
	require.Equal(t, []byte("foobar"), closePackets[0].payload)

	time.Sleep(dur)
	require.Eventually(t, func() bool {
		_, ok := m.Get(connID)
		return !ok
	}, time.Second, 10*time.Millisecond)
}

func TestPacketHandlerMapReplaceWithRemoteClosed(t *testing.T) {
	var closePackets []closePacket
	m := newPacketHandlerMap(nil, func(p closePacket) { closePackets = append(closePackets, p) }, utils.DefaultLogger)
	dur := scaleDuration(50 * time.Millisecond)
	m.deleteRetiredConnsAfter = dur

	handler := &mockPacketHandler{}
	connID := protocol.ParseConnectionID([]byte{4, 3, 2, 1})
	require.True(t, m.Add(connID, handler))
	m.ReplaceWithClosed([]protocol.ConnectionID{connID}, nil)
	h, ok := m.Get(connID)
	require.True(t, ok)
	require.NotEqual(t, handler, h)
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
	h.handlePacket(receivedPacket{remoteAddr: addr})
	require.Empty(t, closePackets)

	time.Sleep(dur)
	require.Eventually(t, func() bool {
		_, ok := m.Get(connID)
		return !ok
	}, time.Second, 10*time.Millisecond)
}

func TestPacketHandlerMapClose(t *testing.T) {
	m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
	testErr := errors.New("shutdown")
	const numConns = 10
	destroyChan := make(chan error, 2*numConns)
	for i := 0; i < numConns; i++ {
		conn := &mockPacketHandler{destruction: destroyChan}
		b := make([]byte, 12)
		rand.Read(b)
		m.Add(protocol.ParseConnectionID(b), conn)
	}
	m.Close(testErr)
	// check that Close can be called multiple times
	m.Close(errors.New("close"))

	for i := 0; i < numConns; i++ {
		select {
		case err := <-destroyChan:
			require.Equal(t, testErr, err)
		default:
			t.Fatalf("connection not destroyed")
		}
	}
	select {
	case err := <-destroyChan:
		t.Fatalf("connection destroyed more than once: %s", err)
	default:
	}
}
