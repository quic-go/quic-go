package ackhandler

import (
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestReceivedPacketHistorySingleRange(t *testing.T) {
	hist := newReceivedPacketHistory()

	require.True(t, hist.ReceivedPacket(4))
	require.Equal(t, []interval{{Start: 4, End: 4}}, slices.Collect(hist.Backward()))

	// add a duplicate packet
	require.False(t, hist.ReceivedPacket(4))
	require.Equal(t, []interval{{Start: 4, End: 4}}, slices.Collect(hist.Backward()))

	// add a few more packets to extend the range
	require.True(t, hist.ReceivedPacket(5))
	require.True(t, hist.ReceivedPacket(6))
	require.Equal(t, []interval{{Start: 4, End: 6}}, slices.Collect(hist.Backward()))

	// add a duplicate within this range
	require.False(t, hist.ReceivedPacket(5))
	require.Equal(t, []interval{{Start: 4, End: 6}}, slices.Collect(hist.Backward()))

	// extend the range at the front
	require.True(t, hist.ReceivedPacket(3))
	require.Equal(t, []interval{{Start: 3, End: 6}}, slices.Collect(hist.Backward()))
}

func TestReceivedPacketHistoryRanges(t *testing.T) {
	hist := newReceivedPacketHistory()
	require.Equal(t, protocol.InvalidPacketNumber, hist.HighestMissingUpTo(1000))

	require.True(t, hist.ReceivedPacket(4))
	require.Equal(t, protocol.PacketNumber(3), hist.HighestMissingUpTo(1000))
	require.Equal(t, protocol.PacketNumber(3), hist.HighestMissingUpTo(4))
	require.Equal(t, protocol.PacketNumber(3), hist.HighestMissingUpTo(3))
	require.Equal(t, protocol.PacketNumber(2), hist.HighestMissingUpTo(2))
	require.True(t, hist.ReceivedPacket(10))
	require.Equal(t, protocol.PacketNumber(9), hist.HighestMissingUpTo(1000))
	require.Equal(t, []interval{
		{Start: 10, End: 10},
		{Start: 4, End: 4},
	}, slices.Collect(hist.Backward()))

	// create a new range in the middle
	require.True(t, hist.ReceivedPacket(7))
	require.Equal(t, []interval{
		{Start: 10, End: 10},
		{Start: 7, End: 7},
		{Start: 4, End: 4},
	}, slices.Collect(hist.Backward()))

	// create a new range at the front
	require.True(t, hist.ReceivedPacket(1))
	require.Equal(t, []interval{
		{Start: 10, End: 10},
		{Start: 7, End: 7},
		{Start: 4, End: 4},
		{Start: 1, End: 1},
	}, slices.Collect(hist.Backward()))

	// extend an existing range at the end
	require.True(t, hist.ReceivedPacket(8))
	require.Equal(t, []interval{
		{Start: 10, End: 10},
		{Start: 7, End: 8},
		{Start: 4, End: 4},
		{Start: 1, End: 1},
	}, slices.Collect(hist.Backward()))

	// extend an existing range at the front
	require.True(t, hist.ReceivedPacket(6))
	require.Equal(t, []interval{
		{Start: 10, End: 10},
		{Start: 6, End: 8},
		{Start: 4, End: 4},
		{Start: 1, End: 1},
	}, slices.Collect(hist.Backward()))

	// close a range
	require.True(t, hist.ReceivedPacket(9))
	require.Equal(t, []interval{
		{Start: 6, End: 10},
		{Start: 4, End: 4},
		{Start: 1, End: 1},
	}, slices.Collect(hist.Backward()))
}

func TestReceivedPacketHistoryMaxNumAckRanges(t *testing.T) {
	hist := newReceivedPacketHistory()

	for i := range protocol.MaxNumAckRanges {
		require.True(t, hist.ReceivedPacket(protocol.PacketNumber(2*i)))
	}
	require.Len(t, hist.ranges, protocol.MaxNumAckRanges)
	require.Equal(t, interval{Start: 0, End: 0}, hist.ranges[0])

	hist.ReceivedPacket(2*protocol.MaxNumAckRanges + 1000)
	// check that the oldest ACK range was deleted
	require.Len(t, hist.ranges, protocol.MaxNumAckRanges)
	require.Equal(t, interval{Start: 2, End: 2}, hist.ranges[0])
}

func TestReceivedPacketHistoryDeleteBelow(t *testing.T) {
	hist := newReceivedPacketHistory()

	hist.DeleteBelow(2)
	require.Empty(t, slices.Collect(hist.Backward()))

	require.True(t, hist.ReceivedPacket(2))
	require.True(t, hist.ReceivedPacket(4))
	require.True(t, hist.ReceivedPacket(5))
	require.True(t, hist.ReceivedPacket(6))
	require.True(t, hist.ReceivedPacket(10))

	require.Equal(t, protocol.PacketNumber(3), hist.HighestMissingUpTo(6))
	hist.DeleteBelow(6)
	require.Equal(t, protocol.InvalidPacketNumber, hist.HighestMissingUpTo(6))
	require.Equal(t, protocol.PacketNumber(9), hist.HighestMissingUpTo(10))
	require.Equal(t, []interval{
		{Start: 10, End: 10},
		{Start: 6, End: 6},
	}, slices.Collect(hist.Backward()))

	// deleting from an existing range
	require.True(t, hist.ReceivedPacket(7))
	require.True(t, hist.ReceivedPacket(8))
	hist.DeleteBelow(7)
	require.Equal(t, []interval{
		{Start: 10, End: 10},
		{Start: 7, End: 8},
	}, slices.Collect(hist.Backward()))

	// keep a one-packet range
	hist.DeleteBelow(10)
	require.Equal(t, []interval{{Start: 10, End: 10}}, slices.Collect(hist.Backward()))

	// delayed packets below deleted ranges are ignored
	require.False(t, hist.ReceivedPacket(5))
	require.Equal(t, []interval{{Start: 10, End: 10}}, slices.Collect(hist.Backward()))
}

func TestReceivedPacketHistoryDuplicateDetection(t *testing.T) {
	hist := newReceivedPacketHistory()

	require.False(t, hist.IsPotentiallyDuplicate(5))

	require.True(t, hist.ReceivedPacket(4))
	require.True(t, hist.ReceivedPacket(5))
	require.True(t, hist.ReceivedPacket(6))
	require.True(t, hist.ReceivedPacket(8))
	require.True(t, hist.ReceivedPacket(9))

	require.False(t, hist.IsPotentiallyDuplicate(3))
	require.True(t, hist.IsPotentiallyDuplicate(4))
	require.True(t, hist.IsPotentiallyDuplicate(5))
	require.True(t, hist.IsPotentiallyDuplicate(6))
	require.False(t, hist.IsPotentiallyDuplicate(7))
	require.True(t, hist.IsPotentiallyDuplicate(8))
	require.True(t, hist.IsPotentiallyDuplicate(9))
	require.False(t, hist.IsPotentiallyDuplicate(10))

	// delete and check for potential duplicates
	hist.DeleteBelow(8)
	require.True(t, hist.IsPotentiallyDuplicate(7))
	require.True(t, hist.IsPotentiallyDuplicate(8))
	require.True(t, hist.IsPotentiallyDuplicate(9))
	require.False(t, hist.IsPotentiallyDuplicate(10))
}

func TestReceivedPacketHistoryRandomized(t *testing.T) {
	hist := newReceivedPacketHistory()
	packets := make(map[protocol.PacketNumber]struct{})
	const num = 2 * protocol.MaxNumAckRanges
	numLostPackets := rand.IntN(protocol.MaxNumAckRanges)
	numRcvdPackets := num - numLostPackets

	for i := range num {
		packets[protocol.PacketNumber(i)] = struct{}{}
	}
	lostPackets := make([]protocol.PacketNumber, 0, numLostPackets)
	for len(lostPackets) < numLostPackets {
		p := protocol.PacketNumber(rand.IntN(num - 1)) // lose a random packet, but not the last one
		if _, ok := packets[p]; ok {
			lostPackets = append(lostPackets, p)
			delete(packets, p)
		}
	}
	slices.Sort(lostPackets)
	t.Logf("Losing packets: %v", lostPackets)

	ordered := make([]protocol.PacketNumber, 0, numRcvdPackets)
	for p := range packets {
		ordered = append(ordered, p)
	}
	rand.Shuffle(len(ordered), func(i, j int) { ordered[i], ordered[j] = ordered[j], ordered[i] })

	t.Logf("Receiving packets: %v", ordered)
	for i, p := range ordered {
		require.True(t, hist.ReceivedPacket(p))
		// sometimes receive a duplicate
		if i > 0 && rand.Int()%5 == 0 {
			require.False(t, hist.ReceivedPacket(ordered[rand.IntN(i)]))
		}
	}
	var counter int
	ackRanges := slices.Collect(hist.Backward())
	t.Logf("ACK ranges: %v", ackRanges)
	require.LessOrEqual(t, len(ackRanges), numLostPackets+1)
	for _, ackRange := range ackRanges {
		for p := ackRange.Start; p <= ackRange.End; p++ {
			counter++
			require.Contains(t, packets, p)
		}
	}
	require.Equal(t, numRcvdPackets, counter)

	deletedBelow := protocol.PacketNumber(rand.IntN(num * 2 / 3))
	t.Logf("Deleting below %d", deletedBelow)
	hist.DeleteBelow(deletedBelow)
	for pn := range protocol.PacketNumber(num) {
		if pn < deletedBelow {
			require.Equal(t, protocol.InvalidPacketNumber, hist.HighestMissingUpTo(pn))
			continue
		}
		expected := protocol.InvalidPacketNumber
		for _, lost := range lostPackets {
			if lost < deletedBelow {
				continue
			}
			if lost > pn {
				break
			}
			expected = lost
		}
		hm := hist.HighestMissingUpTo(pn)
		require.Equalf(t, expected, hm, "highest missing up to %d: %d", pn, hm)
	}
}

func BenchmarkHistoryReceiveSequentialPackets(b *testing.B) {
	hist := newReceivedPacketHistory()
	var pn protocol.PacketNumber
	for b.Loop() {
		hist.ReceivedPacket(pn)
		pn++
	}
}

// Packets are received sequentially, with occasional gaps
func BenchmarkHistoryReceiveCommonCase(b *testing.B) {
	hist := newReceivedPacketHistory()
	var pn protocol.PacketNumber
	for b.Loop() {
		hist.ReceivedPacket(pn)
		pn++
		if pn%2000 == 0 {
			pn += 4
		}
	}
}

func BenchmarkHistoryReceiveSequentialPacketsWithGaps(b *testing.B) {
	hist := newReceivedPacketHistory()
	var pn protocol.PacketNumber
	for b.Loop() {
		hist.ReceivedPacket(pn)
		pn += 2
	}
}

func BenchmarkHistoryReceiveReversePacketsWithGaps(b *testing.B) {
	hist := newReceivedPacketHistory()
	for i := 0; i < b.N; i++ {
		hist.ReceivedPacket(protocol.PacketNumber(2 * (b.N - i)))
	}
}

func BenchmarkHistoryIsDuplicate(b *testing.B) {
	b.ReportAllocs()
	hist := newReceivedPacketHistory()
	var pn protocol.PacketNumber
	for range protocol.MaxNumAckRanges {
		for range 5 {
			hist.ReceivedPacket(pn)
			pn++
		}
		pn += 5 // create a gap
	}

	var p protocol.PacketNumber
	for b.Loop() {
		hist.IsPotentiallyDuplicate(p % pn)
		p++
	}
}
