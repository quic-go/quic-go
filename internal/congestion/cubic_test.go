package congestion

import (
	"math"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

const (
	numConnections         uint32  = 2
	nConnectionBeta        float32 = (float32(numConnections) - 1 + beta) / float32(numConnections)
	nConnectionBetaLastMax float32 = (float32(numConnections) - 1 + betaLastMax) / float32(numConnections)
	nConnectionAlpha       float32 = 3 * float32(numConnections) * float32(numConnections) * (1 - nConnectionBeta) / (1 + nConnectionBeta)
	maxCubicTimeInterval           = 30 * time.Millisecond
)

func renoCwnd(currentCwnd protocol.ByteCount) protocol.ByteCount {
	return currentCwnd + protocol.ByteCount(float32(maxDatagramSize)*nConnectionAlpha*float32(maxDatagramSize)/float32(currentCwnd))
}

func cubicConvexCwnd(initialCwnd protocol.ByteCount, rtt, elapsedTime time.Duration) protocol.ByteCount {
	offset := protocol.ByteCount((elapsedTime+rtt)/time.Microsecond) << 10 / 1000000
	deltaCongestionWindow := 410 * offset * offset * offset * maxDatagramSize >> 40
	return initialCwnd + deltaCongestionWindow
}

func TestCubicAboveOriginWithTighterBounds(t *testing.T) {
	clock := mockClock{}
	cubic := NewCubic(&clock)
	cubic.SetNumConnections(int(numConnections))

	// Convex growth.
	const rttMin = 100 * time.Millisecond
	const rttMinS = float32(rttMin/time.Millisecond) / 1000.0
	currentCwnd := 10 * maxDatagramSize
	initialCwnd := currentCwnd

	clock.Advance(time.Millisecond)
	initialTime := clock.Now()
	expectedFirstCwnd := renoCwnd(currentCwnd)
	currentCwnd = cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, initialTime)
	require.Equal(t, expectedFirstCwnd, currentCwnd)

	// Normal TCP phase.
	// The maximum number of expected reno RTTs can be calculated by
	// finding the point where the cubic curve and the reno curve meet.
	maxRenoRtts := int(math.Sqrt(float64(nConnectionAlpha/(0.4*rttMinS*rttMinS*rttMinS))) - 2)
	for range maxRenoRtts {
		numAcksThisEpoch := int(float32(currentCwnd/maxDatagramSize) / nConnectionAlpha)

		initialCwndThisEpoch := currentCwnd
		for range numAcksThisEpoch {
			// Call once per ACK.
			expectedNextCwnd := renoCwnd(currentCwnd)
			currentCwnd = cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now())
			require.Equal(t, expectedNextCwnd, currentCwnd)
		}
		cwndChangeThisEpoch := currentCwnd - initialCwndThisEpoch
		require.InDelta(t, float64(maxDatagramSize), float64(cwndChangeThisEpoch), float64(maxDatagramSize)/2)
		clock.Advance(100 * time.Millisecond)
	}

	for range 54 {
		maxAcksThisEpoch := currentCwnd / maxDatagramSize
		interval := time.Duration(100*1000/maxAcksThisEpoch) * time.Microsecond
		for range int(maxAcksThisEpoch) {
			clock.Advance(interval)
			currentCwnd = cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now())
			expectedCwnd := cubicConvexCwnd(initialCwnd, rttMin, clock.Now().Sub(initialTime))
			require.Equal(t, expectedCwnd, currentCwnd)
		}
	}
	expectedCwnd := cubicConvexCwnd(initialCwnd, rttMin, clock.Now().Sub(initialTime))
	currentCwnd = cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now())
	require.Equal(t, expectedCwnd, currentCwnd)
}

func TestCubicAboveOriginWithFineGrainedCubing(t *testing.T) {
	clock := mockClock{}
	cubic := NewCubic(&clock)
	cubic.SetNumConnections(int(numConnections))

	currentCwnd := 1000 * maxDatagramSize
	initialCwnd := currentCwnd
	rttMin := 100 * time.Millisecond
	clock.Advance(time.Millisecond)
	initialTime := clock.Now()

	currentCwnd = cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now())
	clock.Advance(600 * time.Millisecond)
	currentCwnd = cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now())

	for i := 0; i < 100; i++ {
		clock.Advance(10 * time.Millisecond)
		expectedCwnd := cubicConvexCwnd(initialCwnd, rttMin, clock.Now().Sub(initialTime))
		nextCwnd := cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now())
		require.Equal(t, expectedCwnd, nextCwnd)
		require.Greater(t, nextCwnd, currentCwnd)
		cwndDelta := nextCwnd - currentCwnd
		require.Less(t, cwndDelta, maxDatagramSize/10)
		currentCwnd = nextCwnd
	}
}

func TestCubicHandlesPerAckUpdates(t *testing.T) {
	clock := mockClock{}
	cubic := NewCubic(&clock)
	cubic.SetNumConnections(int(numConnections))

	initialCwndPackets := 150
	currentCwnd := protocol.ByteCount(initialCwndPackets) * maxDatagramSize
	rttMin := 350 * time.Millisecond

	clock.Advance(time.Millisecond)
	rCwnd := renoCwnd(currentCwnd)
	currentCwnd = cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now())
	initialCwnd := currentCwnd

	maxAcks := int(float32(initialCwndPackets) / nConnectionAlpha)
	interval := maxCubicTimeInterval / time.Duration(maxAcks+1)

	clock.Advance(interval)
	rCwnd = renoCwnd(rCwnd)
	require.Equal(t, currentCwnd, cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now()))

	for range maxAcks - 1 {
		clock.Advance(interval)
		nextCwnd := cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now())
		rCwnd = renoCwnd(rCwnd)
		require.Greater(t, nextCwnd, currentCwnd)
		require.Equal(t, rCwnd, nextCwnd)
		currentCwnd = nextCwnd
	}

	minimumExpectedIncrease := maxDatagramSize * 9 / 10
	require.Greater(t, currentCwnd, initialCwnd+minimumExpectedIncrease)
}

func TestCubicHandlesLossEvents(t *testing.T) {
	clock := mockClock{}
	cubic := NewCubic(&clock)
	cubic.SetNumConnections(int(numConnections))

	rttMin := 100 * time.Millisecond
	currentCwnd := 422 * maxDatagramSize
	expectedCwnd := renoCwnd(currentCwnd)

	clock.Advance(time.Millisecond)
	require.Equal(t, expectedCwnd, cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now()))

	preLossCwnd := currentCwnd
	require.Zero(t, cubic.lastMaxCongestionWindow)
	expectedCwnd = protocol.ByteCount(float32(currentCwnd) * nConnectionBeta)
	require.Equal(t, expectedCwnd, cubic.CongestionWindowAfterPacketLoss(currentCwnd))
	require.Equal(t, preLossCwnd, cubic.lastMaxCongestionWindow)
	currentCwnd = expectedCwnd

	preLossCwnd = currentCwnd
	expectedCwnd = protocol.ByteCount(float32(currentCwnd) * nConnectionBeta)
	require.Equal(t, expectedCwnd, cubic.CongestionWindowAfterPacketLoss(currentCwnd))
	currentCwnd = expectedCwnd
	require.Greater(t, preLossCwnd, cubic.lastMaxCongestionWindow)
	expectedLastMax := protocol.ByteCount(float32(preLossCwnd) * nConnectionBetaLastMax)
	require.Equal(t, expectedLastMax, cubic.lastMaxCongestionWindow)
	require.Less(t, expectedCwnd, cubic.lastMaxCongestionWindow)

	currentCwnd = cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now())
	require.Greater(t, cubic.lastMaxCongestionWindow, currentCwnd)

	currentCwnd = cubic.lastMaxCongestionWindow - 1
	preLossCwnd = currentCwnd
	expectedCwnd = protocol.ByteCount(float32(currentCwnd) * nConnectionBeta)
	require.Equal(t, expectedCwnd, cubic.CongestionWindowAfterPacketLoss(currentCwnd))
	expectedLastMax = preLossCwnd
	require.Equal(t, expectedLastMax, cubic.lastMaxCongestionWindow)
}

func TestCubicBelowOrigin(t *testing.T) {
	clock := mockClock{}
	cubic := NewCubic(&clock)
	cubic.SetNumConnections(int(numConnections))

	rttMin := 100 * time.Millisecond
	currentCwnd := 422 * maxDatagramSize
	expectedCwnd := renoCwnd(currentCwnd)

	clock.Advance(time.Millisecond)
	require.Equal(t, expectedCwnd, cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now()))

	expectedCwnd = protocol.ByteCount(float32(currentCwnd) * nConnectionBeta)
	require.Equal(t, expectedCwnd, cubic.CongestionWindowAfterPacketLoss(currentCwnd))
	currentCwnd = expectedCwnd

	currentCwnd = cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now())

	for range 40 {
		clock.Advance(100 * time.Millisecond)
		currentCwnd = cubic.CongestionWindowAfterAck(maxDatagramSize, currentCwnd, rttMin, clock.Now())
	}
	expectedCwnd = 553632 * maxDatagramSize / 1460
	require.Equal(t, expectedCwnd, currentCwnd)
}
