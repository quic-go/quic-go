package ackhandler

import (
	"math"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestSequentialPacketNumberGenerator(t *testing.T) {
	const initialPN protocol.PacketNumber = 123
	png := newSequentialPacketNumberGenerator(initialPN)

	for i := initialPN; i < initialPN+1000; i++ {
		require.Equal(t, i, png.Peek())
		require.Equal(t, i, png.Peek())
		skipNext, pn := png.Pop()
		require.False(t, skipNext)
		require.Equal(t, i, pn)
	}
}

func TestSkippingPacketNumberGeneratorMaxPeriod(t *testing.T) {
	require.Less(t, 2*protocol.SkipPacketMaxPeriod, int64(math.MaxInt32))
}

func TestSkippingPacketNumberGeneratorPeekPop(t *testing.T) {
	const initialPN protocol.PacketNumber = 8
	const initialPeriod protocol.PacketNumber = 25
	const maxPeriod protocol.PacketNumber = 300

	png := newSkippingPacketNumberGenerator(initialPN, initialPeriod, maxPeriod).(*skippingPacketNumberGenerator)
	require.Equal(t, initialPN, png.Peek())
	require.Equal(t, initialPN, png.Peek())
	skipped, pn := png.Pop()
	require.Equal(t, initialPN, pn)
	next := initialPN + 1
	if skipped {
		next++
	}
	require.Equal(t, next, png.Peek())
	require.Equal(t, next, png.Peek())
}

func TestSkippingPacketNumberGeneratorSkipsPacket(t *testing.T) {
	const initialPN protocol.PacketNumber = 8
	const initialPeriod protocol.PacketNumber = 25
	const maxPeriod protocol.PacketNumber = 300

	png := newSkippingPacketNumberGenerator(initialPN, initialPeriod, maxPeriod)
	var last protocol.PacketNumber
	var skipped bool
	for i := 0; i < int(maxPeriod); i++ {
		didSkip, num := png.Pop()
		if didSkip {
			skipped = true
			_, nextNum := png.Pop()
			require.Equal(t, num+1, nextNum)
			break
		}
		if i != 0 {
			require.Equal(t, last+1, num)
		}
		last = num
	}
	require.True(t, skipped)
}

func TestSkippingPacketNumberGeneratorPeriods(t *testing.T) {
	const initialPN protocol.PacketNumber = 8
	const initialPeriod protocol.PacketNumber = 25
	const maxPeriod protocol.PacketNumber = 300

	const rep = 2500
	periods := make([][]protocol.PacketNumber, rep)
	expectedPeriods := []protocol.PacketNumber{25, 50, 100, 200, 300, 300, 300}

	for i := 0; i < rep; i++ {
		png := newSkippingPacketNumberGenerator(initialPN, initialPeriod, maxPeriod)
		lastSkip := initialPN
		for len(periods[i]) < len(expectedPeriods) {
			skipNext, next := png.Pop()
			if skipNext {
				skipped := next + 1
				require.Greater(t, skipped, lastSkip+1)
				periods[i] = append(periods[i], skipped-lastSkip-1)
				lastSkip = skipped
			}
		}
	}

	for j := 0; j < len(expectedPeriods); j++ {
		var average float64
		for i := 0; i < rep; i++ {
			average += float64(periods[i][j]) / float64(len(periods))
		}
		t.Logf("period %d: %.2f (expected %d)\n", j, average, expectedPeriods[j])
		tolerance := protocol.PacketNumber(5)
		if t := expectedPeriods[j] / 10; t > tolerance {
			tolerance = t
		}
		// we never skip two packet numbers at the same time
		require.InDelta(t, float64(expectedPeriods[j]+1), average, float64(tolerance))
	}
}
