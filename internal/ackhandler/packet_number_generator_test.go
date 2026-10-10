package ackhandler

import (
	"math"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestPacketNumberGeneratorWithoutSkipping(t *testing.T) {
	const initialPN protocol.PacketNumber = 123
	png := newPacketNumberGenerator(initialPN, 1, 1)

	for i := initialPN; i < initialPN+1000; i++ {
		require.Equal(t, i, png.Peek(false))
		require.Equal(t, i, png.Peek(false))
		skipNext, pn := png.Pop(false)
		require.False(t, skipNext)
		require.Equal(t, i, pn)
	}
	// Sending crypto packets doesn't consume the application-data skipping period.
	var skipped bool
	for range 6 {
		didSkip, _ := png.Pop(true)
		skipped = skipped || didSkip
	}
	require.True(t, skipped)
}

func TestSkippingPacketNumberGenerator(t *testing.T) {
	// the maximum period must be sufficiently small such that using a 32-bit random number is ok
	require.Less(t, uint64(2*skipPacketMaxPeriod), uint64(math.MaxUint32))

	const initialPeriod = 25
	const maxPeriod = 300

	png := newPacketNumberGenerator(100, initialPeriod, maxPeriod)
	require.Equal(t, protocol.PacketNumber(100), png.Peek(true))
	require.Equal(t, protocol.PacketNumber(100), png.Peek(true))
	require.Equal(t, protocol.PacketNumber(100), png.Peek(true))
	_, pn := png.Pop(true)
	require.Equal(t, protocol.PacketNumber(100), pn)

	var last protocol.PacketNumber
	var skipped bool
	for i := range maxPeriod {
		next := png.Peek(false)
		didSkip, num := png.Pop(false)
		require.False(t, didSkip)
		require.Equal(t, next, num)
		next = png.Peek(true)
		didSkip, num = png.Pop(true)
		require.Equal(t, next, num)
		if didSkip {
			skipped = true
			_, nextNum := png.Pop(true)
			require.Equal(t, num+1, nextNum)
			break
		}
		if i != 0 {
			require.Equal(t, num, last+2)
		}
		last = num
	}
	require.True(t, skipped)
}

func TestSkippingPacketNumberGeneratorPeriods(t *testing.T) {
	const initialPN protocol.PacketNumber = 8
	const initialPeriod = 25
	const maxPeriod = 300

	const rep = 2500
	periods := make([][]protocol.PacketNumber, rep)
	expectedPeriods := []protocol.PacketNumber{25, 50, 100, 200, 300, 300, 300}

	for i := range rep {
		png := newPacketNumberGenerator(initialPN, initialPeriod, maxPeriod)
		lastSkip := initialPN
		for len(periods[i]) < len(expectedPeriods) {
			skipNext, next := png.Pop(true)
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
