package ackhandler

import (
	"slices"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func ackElicitingPacket() *packet {
	return &packet{StreamFrames: []StreamFrame{{Frame: &wire.StreamFrame{StreamID: 1}}}}
}

func (h *sentPacketHistory) getPacketNumbers() []protocol.PacketNumber {
	pns := make([]protocol.PacketNumber, 0, len(h.packets))
	for pn := range h.Packets() {
		pns = append(pns, pn)
	}
	return pns
}

func TestSentPacketHistoryPacketTracking(t *testing.T) {
	t.Run("first packet ack-eliciting", func(t *testing.T) {
		testSentPacketHistoryPacketTracking(t, true)
	})
	t.Run("first packet non-ack-eliciting", func(t *testing.T) {
		testSentPacketHistoryPacketTracking(t, false)
	})
}

func testSentPacketHistoryPacketTracking(t *testing.T, firstPacketAckEliciting bool) {
	hist := newSentPacketHistory(true)

	require.False(t, hist.HasOutstandingPackets())
	if firstPacketAckEliciting {
		hist.SentPacket(0, ackElicitingPacket())
		require.True(t, hist.HasOutstandingPackets())
	} else {
		hist.SentPacket(0, &packet{})
		require.False(t, hist.HasOutstandingPackets())
	}
	hist.SentPacket(1, ackElicitingPacket())
	hist.SentPacket(2, ackElicitingPacket())
	require.Equal(t, []protocol.PacketNumber{0, 1, 2}, hist.getPacketNumbers())
	require.Empty(t, slices.Collect(hist.SkippedPackets()))
	require.Equal(t, 3, hist.Len())

	// non-ack-eliciting packets are saved, but don't count as outstanding
	hist.SentPacket(3, &packet{})
	hist.SentPacket(4, ackElicitingPacket())
	hist.SentPacket(5, &packet{})
	hist.SentPacket(6, ackElicitingPacket())
	require.Equal(t, []protocol.PacketNumber{0, 1, 2, 3, 4, 5, 6}, hist.getPacketNumbers())

	// handle skipped packet numbers
	hist.SkippedPacket(7)
	hist.SentPacket(8, ackElicitingPacket())
	hist.SentPacket(9, &packet{})
	hist.SkippedPacket(10)
	hist.SentPacket(11, ackElicitingPacket())
	require.Equal(t, []protocol.PacketNumber{0, 1, 2, 3, 4, 5, 6, 8, 9, 11}, hist.getPacketNumbers())
	require.Equal(t, []protocol.PacketNumber{7, 10}, slices.Collect(hist.SkippedPackets()))
	require.Equal(t, 12, hist.Len())
}

func TestSentPacketHistoryNonSequentialPacketNumberUse(t *testing.T) {
	hist := newSentPacketHistory(true)
	hist.SentPacket(100, ackElicitingPacket())
	require.Panics(t, func() {
		hist.SentPacket(102, ackElicitingPacket())
	})
}

func TestSentPacketHistoryRemovePackets(t *testing.T) {
	hist := newSentPacketHistory(true)

	hist.SentPacket(0, ackElicitingPacket())
	hist.SentPacket(1, ackElicitingPacket())
	hist.SkippedPacket(2)
	hist.SkippedPacket(3)
	hist.SentPacket(4, ackElicitingPacket())
	hist.SkippedPacket(5)
	hist.SentPacket(6, ackElicitingPacket())
	require.Equal(t, []protocol.PacketNumber{0, 1, 4, 6}, hist.getPacketNumbers())
	require.Equal(t, []protocol.PacketNumber{2, 3, 5}, slices.Collect(hist.SkippedPackets()))

	require.NoError(t, hist.Remove(0))
	require.Equal(t, []protocol.PacketNumber{2, 3, 5}, slices.Collect(hist.SkippedPackets()))
	require.NoError(t, hist.Remove(1))
	require.Equal(t, []protocol.PacketNumber{4, 6}, hist.getPacketNumbers())
	// skipped packets should be preserved
	require.Equal(t, []protocol.PacketNumber{2, 3, 5}, slices.Collect(hist.SkippedPackets()))

	// add one more packet
	hist.SentPacket(7, ackElicitingPacket())
	require.Equal(t, []protocol.PacketNumber{4, 6, 7}, hist.getPacketNumbers())

	// remove last packet and add another
	require.NoError(t, hist.Remove(7))
	hist.SentPacket(8, ackElicitingPacket())
	require.Equal(t, []protocol.PacketNumber{4, 6, 8}, hist.getPacketNumbers())

	// try to remove non-existent packet
	err := hist.Remove(9)
	require.Error(t, err)
	require.EqualError(t, err, "packet 9 not found in sent packet history")

	// only the last 4 skipped packets should be preserved
	hist.SkippedPacket(9)
	hist.SkippedPacket(10)
	hist.SentPacket(11, ackElicitingPacket())
	hist.SkippedPacket(12)
	require.Equal(t, []protocol.PacketNumber{5, 9, 10, 12}, slices.Collect(hist.SkippedPackets()))

	// Remove all packets
	require.NoError(t, hist.Remove(4))
	require.NoError(t, hist.Remove(6))
	require.NoError(t, hist.Remove(8))
	require.NoError(t, hist.Remove(11))
	require.Empty(t, hist.getPacketNumbers())
	require.Len(t, slices.Collect(hist.SkippedPackets()), 4)
	require.False(t, hist.HasOutstandingPackets())
}

func TestSentPacketHistoryFirstOutstandingPacket(t *testing.T) {
	hist := newSentPacketHistory(true)

	pn, p := hist.FirstOutstanding()
	require.Equal(t, protocol.InvalidPacketNumber, pn)
	require.Nil(t, p)

	hist.SentPacket(2, ackElicitingPacket())
	hist.SentPacket(3, ackElicitingPacket())
	pn, p = hist.FirstOutstanding()
	require.Equal(t, protocol.PacketNumber(2), pn)
	require.NotNil(t, p)

	// remove the first packet
	hist.Remove(2)
	pn, p = hist.FirstOutstanding()
	require.Equal(t, protocol.PacketNumber(3), pn)
	require.NotNil(t, p)

	// Path MTU packets are not regarded as outstanding
	hist = newSentPacketHistory(true)
	hist.SentPacket(2, ackElicitingPacket())
	hist.SkippedPacket(3)
	p = ackElicitingPacket()
	p.IsPathMTUProbePacket = true
	hist.SentPacket(4, p)
	pn, p = hist.FirstOutstanding()
	require.NotNil(t, p)
	require.Equal(t, protocol.PacketNumber(2), pn)
}

func TestSentPacketHistoryIterating(t *testing.T) {
	hist := newSentPacketHistory(true)
	hist.SkippedPacket(0)
	hist.SentPacket(1, ackElicitingPacket())
	hist.SentPacket(2, ackElicitingPacket())
	hist.SentPacket(3, ackElicitingPacket())
	hist.SkippedPacket(4)
	hist.SkippedPacket(5)
	hist.SentPacket(6, ackElicitingPacket())
	require.Equal(t, []protocol.PacketNumber{0, 4, 5}, slices.Collect(hist.SkippedPackets()))
	require.NoError(t, hist.Remove(3))

	var packets []protocol.PacketNumber
	for pn, p := range hist.Packets() {
		require.NotNil(t, p)
		packets = append(packets, pn)
	}

	require.Equal(t, []protocol.PacketNumber{1, 2, 6}, packets)
	require.Equal(t, []protocol.PacketNumber{0, 4, 5}, slices.Collect(hist.SkippedPackets()))
}

func TestSentPacketHistoryDeleteWhileIterating(t *testing.T) {
	hist := newSentPacketHistory(true)
	hist.SentPacket(0, ackElicitingPacket())
	hist.SentPacket(1, ackElicitingPacket())
	hist.SkippedPacket(2)
	hist.SentPacket(3, ackElicitingPacket())
	hist.SkippedPacket(4)
	hist.SentPacket(5, ackElicitingPacket())

	var iterations []protocol.PacketNumber
	for pn := range hist.Packets() {
		iterations = append(iterations, pn)
		switch pn {
		case 0:
			require.NoError(t, hist.Remove(0))
		case 3:
			require.NoError(t, hist.Remove(3))
		}
	}

	require.Equal(t, []protocol.PacketNumber{0, 1, 3, 5}, iterations)
	require.Equal(t, []protocol.PacketNumber{1, 5}, hist.getPacketNumbers())
	require.Equal(t, []protocol.PacketNumber{2, 4}, slices.Collect(hist.SkippedPackets()))
}

func TestSentPacketHistoryPathProbes(t *testing.T) {
	hist := newSentPacketHistory(true)
	hist.SentPacket(0, ackElicitingPacket())
	hist.SentPacket(1, ackElicitingPacket())
	hist.SentPathProbePacket(2, ackElicitingPacket())
	hist.SentPacket(3, ackElicitingPacket())
	hist.SentPacket(4, ackElicitingPacket())
	hist.SentPathProbePacket(5, ackElicitingPacket())

	getPacketsInHistory := func(t *testing.T) []protocol.PacketNumber {
		t.Helper()
		var pns []protocol.PacketNumber
		for pn, p := range hist.Packets() {
			pns = append(pns, pn)
			switch pn {
			case 2, 5:
				require.True(t, p.isPathProbePacket)
			default:
				require.False(t, p.isPathProbePacket)
			}
		}
		return pns
	}

	getPacketsInPathProbeHistory := func(t *testing.T) []protocol.PacketNumber {
		t.Helper()
		var pns []protocol.PacketNumber
		for pn := range hist.PathProbes() {
			pns = append(pns, pn)
		}
		return pns
	}

	require.Equal(t, []protocol.PacketNumber{0, 1, 2, 3, 4, 5}, getPacketsInHistory(t))
	require.Equal(t, []protocol.PacketNumber{2, 5}, getPacketsInPathProbeHistory(t))

	// Removing packets from the regular packet history might happen before the path probe
	// is declared lost, as the original path might have a smaller RTT than the path timeout.
	// Therefore, the path probe packet is not removed from the path probe history.
	require.NoError(t, hist.Remove(0))
	require.NoError(t, hist.Remove(1))
	require.NoError(t, hist.Remove(2))
	require.NoError(t, hist.Remove(3))
	require.Equal(t, []protocol.PacketNumber{4, 5}, getPacketsInHistory(t))
	require.Equal(t, []protocol.PacketNumber{2, 5}, getPacketsInPathProbeHistory(t))
	require.True(t, hist.HasOutstandingPackets())
	require.True(t, hist.HasOutstandingPathProbes())
	pn, p := hist.FirstOutstanding()
	require.Equal(t, protocol.PacketNumber(4), pn)
	require.NotNil(t, p)
	pn, p = hist.FirstOutstandingPathProbe()
	require.NotNil(t, p)
	require.Equal(t, protocol.PacketNumber(2), pn)

	hist.RemovePathProbe(2)
	require.Equal(t, []protocol.PacketNumber{4, 5}, getPacketsInHistory(t))
	require.Equal(t, []protocol.PacketNumber{5}, getPacketsInPathProbeHistory(t))
	require.True(t, hist.HasOutstandingPathProbes())
	pn, p = hist.FirstOutstandingPathProbe()
	require.NotNil(t, p)
	require.Equal(t, protocol.PacketNumber(5), pn)

	hist.RemovePathProbe(5)
	require.Equal(t, []protocol.PacketNumber{4, 5}, getPacketsInHistory(t))
	require.Empty(t, getPacketsInPathProbeHistory(t))
	require.True(t, hist.HasOutstandingPackets())
	require.False(t, hist.HasOutstandingPathProbes())
	pn, p = hist.FirstOutstandingPathProbe()
	require.Equal(t, protocol.InvalidPacketNumber, pn)
	require.Nil(t, p)

	require.NoError(t, hist.Remove(4))
	require.NoError(t, hist.Remove(5))
	require.Empty(t, getPacketsInHistory(t))
	require.False(t, hist.HasOutstandingPackets())
	pn, p = hist.FirstOutstanding()
	require.Equal(t, protocol.InvalidPacketNumber, pn)
	require.Nil(t, p)

	// path probe packets are considered outstanding
	hist.SentPathProbePacket(6, ackElicitingPacket())
	require.False(t, hist.HasOutstandingPackets())
	require.True(t, hist.HasOutstandingPathProbes())
	pn, p = hist.FirstOutstandingPathProbe()
	require.NotNil(t, p)
	require.Equal(t, protocol.PacketNumber(6), pn)

	hist.RemovePathProbe(6)
	require.False(t, hist.HasOutstandingPackets())
	pn, p = hist.FirstOutstanding()
	require.Equal(t, protocol.InvalidPacketNumber, pn)
	require.Nil(t, p)
	require.False(t, hist.HasOutstandingPathProbes())
	pn, p = hist.FirstOutstandingPathProbe()
	require.Equal(t, protocol.InvalidPacketNumber, pn)
	require.Nil(t, p)
}

func TestSentPacketHistoryDifference(t *testing.T) {
	hist := newSentPacketHistory(true)
	hist.SentPacket(0, &packet{})
	hist.SentPacket(1, ackElicitingPacket())
	hist.SentPacket(2, ackElicitingPacket())
	hist.SentPacket(3, ackElicitingPacket())
	hist.SkippedPacket(4)
	hist.SkippedPacket(5)
	hist.SentPacket(6, ackElicitingPacket())
	hist.SentPacket(7, &packet{})
	hist.SkippedPacket(8)
	hist.SentPacket(9, ackElicitingPacket())

	require.Zero(t, hist.Difference(1, 1))
	require.Zero(t, hist.Difference(2, 2))
	require.Zero(t, hist.Difference(7, 7))

	require.Equal(t, protocol.PacketNumber(1), hist.Difference(2, 1))
	require.Equal(t, protocol.PacketNumber(2), hist.Difference(3, 1))
	require.Equal(t, protocol.PacketNumber(3), hist.Difference(4, 1))
	require.Equal(t, protocol.PacketNumber(3), hist.Difference(6, 1)) // 4 and 5 were skipped
	require.Equal(t, protocol.PacketNumber(4), hist.Difference(7, 1)) // 4 and 5 were skipped
	require.Equal(t, protocol.PacketNumber(3), hist.Difference(7, 2)) // 4 and 5 were skipped
	require.Equal(t, protocol.PacketNumber(5), hist.Difference(9, 1)) // 4, 5 and 8 were skipped
}
