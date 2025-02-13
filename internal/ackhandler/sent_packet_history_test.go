package ackhandler

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func (h *sentPacketHistory) getPacketNumbers() []protocol.PacketNumber {
	pns := make([]protocol.PacketNumber, 0, len(h.packets))
	for _, p := range h.packets {
		if p != nil && !p.skippedPacket {
			pns = append(pns, p.PacketNumber)
		}
	}
	return pns
}

func (h *sentPacketHistory) getSkippedPacketNumbers() []protocol.PacketNumber {
	var pns []protocol.PacketNumber
	for _, p := range h.packets {
		if p != nil && p.skippedPacket {
			pns = append(pns, p.PacketNumber)
		}
	}
	return pns
}

func TestSentPacketHistoryPacketTracking(t *testing.T) {
	hist := newSentPacketHistory(true)
	now := time.Now()

	require.False(t, hist.HasOutstandingPackets())
	hist.SentAckElicitingPacket(&packet{PacketNumber: 0})
	require.True(t, hist.HasOutstandingPackets())
	hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
	hist.SentAckElicitingPacket(&packet{PacketNumber: 2})
	require.Equal(t, []protocol.PacketNumber{0, 1, 2}, hist.getPacketNumbers())
	require.Empty(t, hist.getSkippedPacketNumbers())
	require.Equal(t, 3, hist.Len())

	// non-ack-eliciting packets are not saved
	hist.SentNonAckElicitingPacket(3)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 4, SendTime: now})
	hist.SentNonAckElicitingPacket(5)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 6, SendTime: now})
	require.Equal(t, []protocol.PacketNumber{0, 1, 2, 4, 6}, hist.getPacketNumbers())

	// handle skipped packet numbers
	hist.SkippedPacket(7)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 8})
	hist.SentNonAckElicitingPacket(9)
	hist.SkippedPacket(10)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 11})
	require.Equal(t, []protocol.PacketNumber{0, 1, 2, 4, 6, 8, 11}, hist.getPacketNumbers())
	require.Equal(t, []protocol.PacketNumber{7, 10}, hist.getSkippedPacketNumbers())
	require.Equal(t, 12, hist.Len())
}

func TestSentPacketHistoryNonSequentialPacketNumberUse(t *testing.T) {
	hist := newSentPacketHistory(true)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 100})
	require.Panics(t, func() {
		hist.SentAckElicitingPacket(&packet{PacketNumber: 102})
	})
}

func TestSentPacketHistoryRemovePackets(t *testing.T) {
	hist := newSentPacketHistory(true)

	hist.SentAckElicitingPacket(&packet{PacketNumber: 0})
	hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
	hist.SkippedPacket(2)
	hist.SkippedPacket(3)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 4})
	hist.SkippedPacket(5)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 6})
	require.Equal(t, []protocol.PacketNumber{0, 1, 4, 6}, hist.getPacketNumbers())
	require.Equal(t, []protocol.PacketNumber{2, 3, 5}, hist.getSkippedPacketNumbers())

	require.NoError(t, hist.Remove(0))
	require.NoError(t, hist.Remove(1))
	require.Equal(t, []protocol.PacketNumber{4, 6}, hist.getPacketNumbers())
	require.Equal(t, []protocol.PacketNumber{2, 3, 5}, hist.getSkippedPacketNumbers())

	// add one more packet
	hist.SentAckElicitingPacket(&packet{PacketNumber: 7})
	require.Equal(t, []protocol.PacketNumber{4, 6, 7}, hist.getPacketNumbers())

	// remove last packet and add another
	require.NoError(t, hist.Remove(7))
	hist.SentAckElicitingPacket(&packet{PacketNumber: 8})
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

	require.Nil(t, hist.FirstOutstanding())

	hist.SentAckElicitingPacket(&packet{PacketNumber: 2})
	hist.SentAckElicitingPacket(&packet{PacketNumber: 3})
	front := hist.FirstOutstanding()
	require.NotNil(t, front)
	require.Equal(t, protocol.PacketNumber(2), front.PacketNumber)

	// remove the first packet
	hist.Remove(2)
	front = hist.FirstOutstanding()
	require.NotNil(t, front)
	require.Equal(t, protocol.PacketNumber(3), front.PacketNumber)

	// Path MTU packets are not regarded as outstanding
	hist = newSentPacketHistory(true)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 2})
	hist.SkippedPacket(3)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 4, IsPathMTUProbePacket: true})
	front = hist.FirstOutstanding()
	require.NotNil(t, front)
	require.Equal(t, protocol.PacketNumber(2), front.PacketNumber)
}

func TestSentPacketHistoryIterating(t *testing.T) {
	hist := newSentPacketHistory(true)
	hist.SkippedPacket(0)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
	hist.SentAckElicitingPacket(&packet{PacketNumber: 2})
	hist.SentAckElicitingPacket(&packet{PacketNumber: 3})
	hist.SkippedPacket(4)
	hist.SkippedPacket(5)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 6})
	require.NoError(t, hist.Remove(3))
	require.NoError(t, hist.Remove(4))

	var packets, skippedPackets []protocol.PacketNumber
	for p := range hist.Packets() {
		if p.skippedPacket {
			skippedPackets = append(skippedPackets, p.PacketNumber)
		} else {
			packets = append(packets, p.PacketNumber)
		}
	}

	require.Equal(t, []protocol.PacketNumber{1, 2, 6}, packets)
	require.Equal(t, []protocol.PacketNumber{0, 5}, skippedPackets)
}

func TestSentPacketHistoryDeleteWhileIterating(t *testing.T) {
	hist := newSentPacketHistory(true)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 0})
	hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
	hist.SkippedPacket(2)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 3})
	hist.SkippedPacket(4)
	hist.SentAckElicitingPacket(&packet{PacketNumber: 5})

	var iterations []protocol.PacketNumber
	for p := range hist.Packets() {
		iterations = append(iterations, p.PacketNumber)
		switch p.PacketNumber {
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
	hist.SentAckElicitingPacket(&packet{PacketNumber: 0})
	hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
	hist.SentPathProbePacket(&packet{PacketNumber: 2})
	hist.SentAckElicitingPacket(&packet{PacketNumber: 3})
	hist.SentAckElicitingPacket(&packet{PacketNumber: 4})
	hist.SentPathProbePacket(&packet{PacketNumber: 5})

	getPacketsInHistory := func(t *testing.T) []protocol.PacketNumber {
		t.Helper()
		var pns []protocol.PacketNumber
		for p := range hist.Packets() {
			pns = append(pns, p.PacketNumber)
			switch p.PacketNumber {
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
		for p := range hist.PathProbes() {
			pns = append(pns, p.PacketNumber)
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
	firstOutstanding := hist.FirstOutstanding()
	require.NotNil(t, firstOutstanding)
	require.Equal(t, protocol.PacketNumber(4), firstOutstanding.PacketNumber)
	firstOutStandingPathProbe := hist.FirstOutstandingPathProbe()
	require.NotNil(t, firstOutStandingPathProbe)
	require.Equal(t, protocol.PacketNumber(2), firstOutStandingPathProbe.PacketNumber)

	hist.RemovePathProbe(2)
	require.Equal(t, []protocol.PacketNumber{4, 5}, getPacketsInHistory(t))
	require.Equal(t, []protocol.PacketNumber{5}, getPacketsInPathProbeHistory(t))
	require.True(t, hist.HasOutstandingPathProbes())
	firstOutStandingPathProbe = hist.FirstOutstandingPathProbe()
	require.NotNil(t, firstOutStandingPathProbe)
	require.Equal(t, protocol.PacketNumber(5), firstOutStandingPathProbe.PacketNumber)

	hist.RemovePathProbe(5)
	require.Equal(t, []protocol.PacketNumber{4, 5}, getPacketsInHistory(t))
	require.Empty(t, getPacketsInPathProbeHistory(t))
	require.True(t, hist.HasOutstandingPackets())
	require.False(t, hist.HasOutstandingPathProbes())
	require.Nil(t, hist.FirstOutstandingPathProbe())

	require.NoError(t, hist.Remove(4))
	require.NoError(t, hist.Remove(5))
	require.Empty(t, getPacketsInHistory(t))
	require.False(t, hist.HasOutstandingPackets())
	require.Nil(t, hist.FirstOutstanding())

	// path probe packets are considered outstanding
	hist.SentPathProbePacket(&packet{PacketNumber: 6})
	require.False(t, hist.HasOutstandingPackets())
	require.True(t, hist.HasOutstandingPathProbes())
	firstOutStandingPathProbe = hist.FirstOutstandingPathProbe()
	require.NotNil(t, firstOutStandingPathProbe)
	require.Equal(t, protocol.PacketNumber(6), firstOutStandingPathProbe.PacketNumber)

	hist.RemovePathProbe(6)
	require.False(t, hist.HasOutstandingPackets())
	require.Nil(t, hist.FirstOutstanding())
	require.False(t, hist.HasOutstandingPathProbes())
	require.Nil(t, hist.FirstOutstandingPathProbe())
}
