package ackhandler

import (
	"math/rand"
	"slices"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestReceivedPacketHistorySingleRange(t *testing.T) {
	hist := newReceivedPacketHistory()

	require.True(t, hist.ReceivedPacket(4))
	require.Equal(t, []wire.AckRange{{Smallest: 4, Largest: 4}}, hist.AppendAckRanges(nil))

	// add a duplicate packet
	require.False(t, hist.ReceivedPacket(4))
	require.Equal(t, []wire.AckRange{{Smallest: 4, Largest: 4}}, hist.AppendAckRanges(nil))

	// add a few more packets to extend the range
	require.True(t, hist.ReceivedPacket(5))
	require.True(t, hist.ReceivedPacket(6))
	require.Equal(t, []wire.AckRange{{Smallest: 4, Largest: 6}}, hist.AppendAckRanges(nil))

	// add a duplicate within this range
	require.False(t, hist.ReceivedPacket(5))
	require.Equal(t, []wire.AckRange{{Smallest: 4, Largest: 6}}, hist.AppendAckRanges(nil))

	// extend the range at the front
	require.True(t, hist.ReceivedPacket(3))
	require.Equal(t, []wire.AckRange{{Smallest: 3, Largest: 6}}, hist.AppendAckRanges(nil))
}

func TestReceivedPacketHistoryRanges(t *testing.T) {
	hist := newReceivedPacketHistory()
	require.Zero(t, hist.GetHighestAckRange())

	require.True(t, hist.ReceivedPacket(4))
	require.True(t, hist.ReceivedPacket(10))
	require.Equal(t, []wire.AckRange{
		{Smallest: 10, Largest: 10},
		{Smallest: 4, Largest: 4},
	}, hist.AppendAckRanges(nil))
	require.Equal(t, wire.AckRange{Smallest: 10, Largest: 10}, hist.GetHighestAckRange())

	// create a new range in the middle
	require.True(t, hist.ReceivedPacket(7))
	require.Equal(t, []wire.AckRange{
		{Smallest: 10, Largest: 10},
		{Smallest: 7, Largest: 7},
		{Smallest: 4, Largest: 4},
	}, hist.AppendAckRanges(nil))

	// create a new range at the front
	require.True(t, hist.ReceivedPacket(1))
	require.Equal(t, []wire.AckRange{
		{Smallest: 10, Largest: 10},
		{Smallest: 7, Largest: 7},
		{Smallest: 4, Largest: 4},
		{Smallest: 1, Largest: 1},
	}, hist.AppendAckRanges(nil))

	// extend an existing range at the end
	require.True(t, hist.ReceivedPacket(8))
	require.Equal(t, []wire.AckRange{
		{Smallest: 10, Largest: 10},
		{Smallest: 7, Largest: 8},
		{Smallest: 4, Largest: 4},
		{Smallest: 1, Largest: 1},
	}, hist.AppendAckRanges(nil))

	// extend an existing range at the front
	require.True(t, hist.ReceivedPacket(6))
	require.Equal(t, []wire.AckRange{
		{Smallest: 10, Largest: 10},
		{Smallest: 6, Largest: 8},
		{Smallest: 4, Largest: 4},
		{Smallest: 1, Largest: 1},
	}, hist.AppendAckRanges(nil))

	// close a range
	require.True(t, hist.ReceivedPacket(9))
	require.Equal(t, []wire.AckRange{
		{Smallest: 6, Largest: 10},
		{Smallest: 4, Largest: 4},
		{Smallest: 1, Largest: 1},
	}, hist.AppendAckRanges(nil))
}

func TestReceivedPacketHistoryMaxNumAckRanges(t *testing.T) {
	hist := newReceivedPacketHistory()

	for i := protocol.PacketNumber(0); i < protocol.MaxNumAckRanges; i++ {
		require.True(t, hist.ReceivedPacket(2*i))
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
	require.Empty(t, hist.AppendAckRanges(nil))

	require.True(t, hist.ReceivedPacket(2))
	require.True(t, hist.ReceivedPacket(4))
	require.True(t, hist.ReceivedPacket(5))
	require.True(t, hist.ReceivedPacket(6))
	require.True(t, hist.ReceivedPacket(10))

	hist.DeleteBelow(6)
	require.Equal(t, []wire.AckRange{
		{Smallest: 10, Largest: 10},
		{Smallest: 6, Largest: 6},
	}, hist.AppendAckRanges(nil))

	// deleting from an existing range
	require.True(t, hist.ReceivedPacket(7))
	require.True(t, hist.ReceivedPacket(8))
	hist.DeleteBelow(7)
	require.Equal(t, []wire.AckRange{
		{Smallest: 10, Largest: 10},
		{Smallest: 7, Largest: 8},
	}, hist.AppendAckRanges(nil))

	// keep a one-packet range
	hist.DeleteBelow(10)
	require.Equal(t, []wire.AckRange{{Smallest: 10, Largest: 10}}, hist.AppendAckRanges(nil))

	// delayed packets below deleted ranges are ignored
	require.False(t, hist.ReceivedPacket(5))
	require.Equal(t, []wire.AckRange{{Smallest: 10, Largest: 10}}, hist.AppendAckRanges(nil))
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
	packets := make(map[protocol.PacketNumber]int)
	const num = 2 * protocol.MaxNumAckRanges
	numLostPackets := rand.Intn(protocol.MaxNumAckRanges)
	numRcvdPackets := num - numLostPackets

	for i := 0; i < num; i++ {
		packets[protocol.PacketNumber(i)] = 0
	}
	lostPackets := make([]protocol.PacketNumber, 0, numLostPackets)
	for len(lostPackets) < numLostPackets {
		p := protocol.PacketNumber(rand.Intn(num))
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
			require.False(t, hist.ReceivedPacket(ordered[rand.Intn(i)]))
		}
	}
	var counter int
	ackRanges := hist.AppendAckRanges(nil)
	t.Logf("ACK ranges: %v", ackRanges)
	require.LessOrEqual(t, len(ackRanges), numLostPackets+1)
	for _, ackRange := range ackRanges {
		for p := ackRange.Smallest; p <= ackRange.Largest; p++ {
			counter++
			require.Contains(t, packets, p)
		}
	}
	require.Equal(t, numRcvdPackets, counter)
}

func BenchmarkHistoryReceiveSequentialPackets(b *testing.B) {
	hist := newReceivedPacketHistory()
	for i := 0; i < b.N; i++ {
		hist.ReceivedPacket(protocol.PacketNumber(i))
	}
}

// Packets are received sequentially, with occasional gaps
func BenchmarkHistoryReceiveCommonCase(b *testing.B) {
	hist := newReceivedPacketHistory()
	var pn protocol.PacketNumber
	for i := 0; i < b.N; i++ {
		hist.ReceivedPacket(pn)
		pn++
		if i%2000 == 0 {
			pn += 4
		}
	}
}

func BenchmarkHistoryReceiveSequentialPacketsWithGaps(b *testing.B) {
	hist := newReceivedPacketHistory()
	for i := 0; i < b.N; i++ {
		hist.ReceivedPacket(protocol.PacketNumber(2 * i))
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
	for i := 0; i < protocol.MaxNumAckRanges; i++ {
		for j := 0; j < 5; j++ {
			hist.ReceivedPacket(pn)
			pn++
		}
		pn += 5 // create a gap
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hist.IsPotentiallyDuplicate(protocol.PacketNumber(i) % pn)
	}
}
