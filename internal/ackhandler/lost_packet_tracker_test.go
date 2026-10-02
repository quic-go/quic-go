package ackhandler

import (
	"maps"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestLostPacketTracker(t *testing.T) {
	lt := newLostPacketTracker()

	start := monotime.Now()
	want := make(map[protocol.PacketNumber]monotime.Time, maxTrackedLostPackets)
	for i := range maxTrackedLostPackets {
		pn := protocol.PacketNumber(i + 1)
		sendTime := start.Add(time.Duration(i))
		lt.Add(pn, sendTime)
		want[pn] = sendTime
	}
	require.Equal(t, want, maps.Collect(lt.All()))

	// Lose one more packet. The first one should be removed.
	lt.Add(maxTrackedLostPackets+1, start.Add(time.Duration(maxTrackedLostPackets)))
	delete(want, 1)
	want[maxTrackedLostPackets+1] = start.Add(time.Duration(maxTrackedLostPackets))
	require.Equal(t, want, maps.Collect(lt.All()))

	lt.Delete(5)
	lt.Delete(10)
	delete(want, 5)
	delete(want, 10)
	require.Equal(t, want, maps.Collect(lt.All()))
}

func TestLostPacketTrackerDeleteBefore(t *testing.T) {
	lt := newLostPacketTracker()

	trackedPackets := func(lt *lostPacketTracker) []protocol.PacketNumber {
		var pns []protocol.PacketNumber
		for pn := range lt.All() {
			pns = append(pns, pn)
		}
		return pns
	}

	start := monotime.Now()
	lt.Add(1, start)
	lt.Add(5, start.Add(time.Second))
	lt.Add(8, start.Add(2*time.Second))
	lt.Add(10, start.Add(3*time.Second))

	require.Equal(t, []protocol.PacketNumber{1, 5, 8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start) // this should be a no-op
	require.Equal(t, []protocol.PacketNumber{1, 5, 8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(2 * time.Second))
	require.Equal(t, []protocol.PacketNumber{8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(time.Second * 5 / 2))
	require.Equal(t, []protocol.PacketNumber{10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(time.Hour))
	require.Empty(t, trackedPackets(lt))
}
