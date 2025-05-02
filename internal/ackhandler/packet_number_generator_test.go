package ackhandler

import (
	"math"
	"testing"

	"github.com/Noooste/quic-go/internal/protocol"

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

func TestSkippingPacketNumberGenerator(t *testing.T) {
	// the maximum period must be sufficiently small such that using a 32-bit random number is ok
	require.Less(t, 2*protocol.SkipPacketMaxPeriod, protocol.PacketNumber(math.MaxInt32))

	const initialPeriod protocol.PacketNumber = 25
	const maxPeriod protocol.PacketNumber = 300

	png := newSkippingPacketNumberGenerator(100, initialPeriod, maxPeriod)
	require.Equal(t, protocol.PacketNumber(100), png.Peek())
	require.Equal(t, protocol.PacketNumber(100), png.Peek())
	require.Equal(t, protocol.PacketNumber(100), png.Peek())
	_, pn := png.Pop()
	require.Equal(t, protocol.PacketNumber(100), pn)

	var last protocol.PacketNumber
	var skipped bool
	for i := range maxPeriod {
		didSkip, num := png.Pop()
		if didSkip {
			skipped = true
			_, nextNum := png.Pop()
			require.Equal(t, num+1, nextNum)
			break
		}
		if i != 0 {
			require.Equal(t, num, last+1)
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

	for i := range rep {
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

	for j := range expectedPeriods {
		var average float64
		for i := range rep {
			average += float64(periods[i][j]) / float64(len(periods))
		}
		t.Logf("Period %d: %.2f (expected %d)\n", j, average, expectedPeriods[j])
		require.InDelta(t,
			float64(expectedPeriods[j]+1),
			average,
			float64(max(protocol.PacketNumber(5), expectedPeriods[j]/10)),
		)
	}
}
