package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestReceivedPacketQueue(t *testing.T) {
	h1 := &pathReceiver{}
	h2 := &pathReceiver{}
	var q receivedPacketQueue
	q.Init(h1)

	push := func(data string, source packetHandler) {
		t.Helper()
		require.True(t, q.Push(receivedPacket{data: []byte(data)}, source))
	}
	requirePop := func(data string, source packetHandler) {
		t.Helper()
		p, s, ok := q.Pop()
		require.True(t, ok)
		require.Equal(t, data, string(p.data))
		require.Same(t, source, s)
	}

	// packets received on other paths are returned first
	push("a", h1)
	push("b", h2)
	requirePop("b", h2)
	requirePop("a", h1)
	require.True(t, q.Empty())

	// switching paths moves the packets of the old path to the side queue
	push("c", h1)
	q.SetActive(h2)
	push("d", h2)
	push("e", h1)
	requirePop("c", h1)
	requirePop("e", h1)
	requirePop("d", h2)

	// switching to the active path doesn't move any packets
	push("f", h2)
	q.SetActive(h2)
	push("g", h1)
	requirePop("g", h1)
	requirePop("f", h2)
	require.True(t, q.Empty())
}

func TestReceivedPacketQueueLimits(t *testing.T) {
	h1 := &pathReceiver{}
	h2 := &pathReceiver{}
	var q receivedPacketQueue
	q.Init(h1)

	// the main and the side queue have their own limit
	for _, h := range []packetHandler{h1, h2} {
		for range protocol.MaxConnUnprocessedPackets {
			require.True(t, q.Push(receivedPacket{}, h))
		}
		require.False(t, q.Push(receivedPacket{}, h))
	}

	// switching paths moves all packets, ignoring the limit of the side queue
	q.SetActive(h2)
	var n int
	for !q.Empty() {
		q.Pop()
		n++
	}
	require.Equal(t, 2*protocol.MaxConnUnprocessedPackets, n)
}

func TestReceivedPacketQueueClear(t *testing.T) {
	h1 := &pathReceiver{}
	h2 := &pathReceiver{}
	var q receivedPacketQueue
	q.Init(h1)

	require.True(t, q.Push(receivedPacket{data: []byte("foo"), buffer: getPacketBuffer()}, h1))
	require.True(t, q.Push(receivedPacket{data: []byte("bar"), buffer: getPacketBuffer()}, h2))
	q.Clear()
	require.True(t, q.Empty())
}
