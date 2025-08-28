package ackhandler

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func (h *sentPacketHistory) getPacketNumbers() []protocol.PacketNumber {
	pns := make([]protocol.PacketNumber, 0, len(h.packets))
	for pn, p := range h.Packets() {
		if p != nil && !p.skippedPacket {
			pns = append(pns, pn)
		}
	}
	return pns
}

func (h *sentPacketHistory) getSkippedPacketNumbers() []protocol.PacketNumber {
	var pns []protocol.PacketNumber
	for pn, p := range h.Packets() {
		if p != nil && p.skippedPacket {
			pns = append(pns, pn)
		}
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
	now := time.Now()

	var firstPacketNumber []protocol.PacketNumber
	require.False(t, hist.HasOutstandingPackets())
	if firstPacketAckEliciting {
		hist.SentAckElicitingPacket(0, &packet{})
		require.True(t, hist.HasOutstandingPackets())
		firstPacketNumber = append(firstPacketNumber, 0)
	} else {
		hist.SentNonAckElicitingPacket(0)
		require.False(t, hist.HasOutstandingPackets())
	}
	hist.SentAckElicitingPacket(1, &packet{})
	hist.SentAckElicitingPacket(2, &packet{})
	require.Equal(t, append(firstPacketNumber, 1, 2), hist.getPacketNumbers())
	require.Empty(t, hist.getSkippedPacketNumbers())
	if firstPacketAckEliciting {
		require.Equal(t, 3, hist.Len())
	} else {
		require.Equal(t, 2, hist.Len())
	}

	// non-ack-eliciting packets are not saved
	hist.SentNonAckElicitingPacket(3)
	hist.SentAckElicitingPacket(4, &packet{SendTime: now})
	hist.SentNonAckElicitingPacket(5)
	hist.SentAckElicitingPacket(6, &packet{SendTime: now})
	require.Equal(t, append(firstPacketNumber, 1, 2, 4, 6), hist.getPacketNumbers())

	// handle skipped packet numbers
	hist.SkippedPacket(7)
	hist.SentAckElicitingPacket(8, &packet{SendTime: now})
	hist.SentNonAckElicitingPacket(9)
	hist.SkippedPacket(10)
	hist.SentAckElicitingPacket(11, &packet{SendTime: now})
	require.Equal(t, append(firstPacketNumber, 1, 2, 4, 6, 8, 11), hist.getPacketNumbers())
	require.Equal(t, []protocol.PacketNumber{7, 10}, hist.getSkippedPacketNumbers())
	if firstPacketAckEliciting {
		require.Equal(t, 12, hist.Len())
	} else {
		require.Equal(t, 11, hist.Len())
	}
}

func TestSentPacketHistoryNonSequentialPacketNumberUse(t *testing.T) {
	hist := newSentPacketHistory(true)
	hist.SentAckElicitingPacket(100, &packet{})
	require.Panics(t, func() {
		hist.SentAckElicitingPacket(102, &packet{})
	})
}

func TestSentPacketHistoryRemovePackets(t *testing.T) {
	hist := newSentPacketHistory(true)

	hist.SentAckElicitingPacket(0, &packet{})
	hist.SentAckElicitingPacket(1, &packet{})
	hist.SkippedPacket(2)
	hist.SkippedPacket(3)
	hist.SentAckElicitingPacket(4, &packet{})
	hist.SkippedPacket(5)
	hist.SentAckElicitingPacket(6, &packet{})
	require.Equal(t, []protocol.PacketNumber{0, 1, 4, 6}, hist.getPacketNumbers())
	require.Equal(t, []protocol.PacketNumber{2, 3, 5}, hist.getSkippedPacketNumbers())

	require.NoError(t, hist.Remove(0))
	require.NoError(t, hist.Remove(1))
	require.Equal(t, []protocol.PacketNumber{4, 6}, hist.getPacketNumbers())
	require.Equal(t, []protocol.PacketNumber{2, 3, 5}, hist.getSkippedPacketNumbers())

	// add one more packet
	hist.SentAckElicitingPacket(7, &packet{})
	require.Equal(t, []protocol.PacketNumber{4, 6, 7}, hist.getPacketNumbers())

	// remove last packet and add another
	require.NoError(t, hist.Remove(7))
	hist.SentAckElicitingPacket(8, &packet{})
	require.Equal(t, []protocol.PacketNumber{4, 6, 8}, hist.getPacketNumbers())

	// try to remove non-existent packet
	err := hist.Remove(9)
	require.Error(t, err)
	require.EqualError(t, err, "packet 9 not found in sent packet history")

	// Remove all packets
	require.NoError(t, hist.Remove(4))
	require.NoError(t, hist.Remove(6))
	require.NoError(t, hist.Remove(8))
	require.Empty(t, hist.getPacketNumbers())
	require.Empty(t, hist.getSkippedPacketNumbers())
	require.False(t, hist.HasOutstandingPackets())
}

func TestSentPacketHistoryFirstOutstandingPacket(t *testing.T) {
	hist := newSentPacketHistory(true)

	pn, p := hist.FirstOutstanding()
	require.Equal(t, protocol.InvalidPacketNumber, pn)
	require.Nil(t, p)

	hist.SentAckElicitingPacket(2, &packet{})
	hist.SentAckElicitingPacket(3, &packet{})
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
	hist.SentAckElicitingPacket(2, &packet{})
	hist.SkippedPacket(3)
	hist.SentAckElicitingPacket(4, &packet{IsPathMTUProbePacket: true})
	pn, p = hist.FirstOutstanding()
	require.NotNil(t, p)
	require.Equal(t, protocol.PacketNumber(2), pn)
}

func TestSentPacketHistoryIterating(t *testing.T) {
	hist := newSentPacketHistory(true)
	hist.SkippedPacket(0)
	hist.SentAckElicitingPacket(1, &packet{})
	hist.SentAckElicitingPacket(2, &packet{})
	hist.SentAckElicitingPacket(3, &packet{})
	hist.SkippedPacket(4)
	hist.SkippedPacket(5)
	hist.SentAckElicitingPacket(6, &packet{})
	require.NoError(t, hist.Remove(3))
	require.NoError(t, hist.Remove(4))

	var packets, skippedPackets []protocol.PacketNumber
	for pn, p := range hist.Packets() {
		if p.skippedPacket {
			skippedPackets = append(skippedPackets, pn)
		} else {
			packets = append(packets, pn)
		}
	}

	require.Equal(t, []protocol.PacketNumber{1, 2, 6}, packets)
	require.Equal(t, []protocol.PacketNumber{0, 5}, skippedPackets)
}

func TestSentPacketHistoryDeleteWhileIterating(t *testing.T) {
	hist := newSentPacketHistory(true)
	hist.SentAckElicitingPacket(0, &packet{})
	hist.SentAckElicitingPacket(1, &packet{})
	hist.SkippedPacket(2)
	hist.SentAckElicitingPacket(3, &packet{})
	hist.SkippedPacket(4)
	hist.SentAckElicitingPacket(5, &packet{})

	var iterations []protocol.PacketNumber
	for pn := range hist.Packets() {
		iterations = append(iterations, pn)
		switch pn {
		case 0:
			require.NoError(t, hist.Remove(0))
		case 4:
			require.NoError(t, hist.Remove(4))
		}
	}

	require.Equal(t, []protocol.PacketNumber{0, 1, 2, 3, 4, 5}, iterations)
	require.Equal(t, []protocol.PacketNumber{1, 3, 5}, hist.getPacketNumbers())
	require.Equal(t, []protocol.PacketNumber{2}, hist.getSkippedPacketNumbers())
}

func TestSentPacketHistoryPathProbes(t *testing.T) {
	hist := newSentPacketHistory(true)
	hist.SentAckElicitingPacket(0, &packet{})
	hist.SentAckElicitingPacket(1, &packet{})
	hist.SentPathProbePacket(2, &packet{})
	hist.SentAckElicitingPacket(3, &packet{})
	hist.SentAckElicitingPacket(4, &packet{})
	hist.SentPathProbePacket(5, &packet{})

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
	hist.SentPathProbePacket(6, &packet{})
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
