package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"

	"github.com/stretchr/testify/require"
)

func TestHybridSlowStartSimpleCase(t *testing.T) {
	slowStart := HybridSlowStart{}

	sentTime := monotime.Now()
	endSendTime := sentTime.Add(2 * time.Millisecond)
	slowStart.StartReceiveRound(endSendTime)

	sentTime = sentTime.Add(time.Millisecond)
	require.False(t, slowStart.IsEndOfRound(sentTime))

	// Test duplicates.
	require.False(t, slowStart.IsEndOfRound(sentTime))

	sentTime = sentTime.Add(time.Millisecond)
	require.False(t, slowStart.IsEndOfRound(sentTime))
	sentTime = sentTime.Add(time.Millisecond)
	require.True(t, slowStart.IsEndOfRound(sentTime))

	// Test without starting a new receive round.
	sentTime = sentTime.Add(time.Millisecond)
	require.True(t, slowStart.IsEndOfRound(sentTime))

	endSendTime = sentTime.Add(15 * time.Millisecond)
	slowStart.StartReceiveRound(endSendTime)
	for sentTime < endSendTime {
		sentTime = sentTime.Add(time.Millisecond)
		require.False(t, slowStart.IsEndOfRound(sentTime))
	}
	sentTime = sentTime.Add(time.Millisecond)
	require.True(t, slowStart.IsEndOfRound(sentTime))
}

func TestHybridSlowStartWithDelay(t *testing.T) {
	slowStart := HybridSlowStart{}
	const rtt = 60 * time.Millisecond
	// We expect to detect the increase at +1/8 of the RTT; hence at a typical
	// RTT of 60ms the detection will happen at 67.5 ms.
	const hybridStartMinSamples = 8 // Number of acks required to trigger.

	endSendTime := monotime.Now()
	slowStart.StartReceiveRound(endSendTime)

	// Will not trigger since our lowest RTT in our burst is the same as the long
	// term RTT provided.
	for n := range hybridStartMinSamples {
		require.False(t, slowStart.ShouldExitSlowStart(rtt+time.Duration(n)*time.Millisecond, rtt, 100))
	}
	endSendTime = endSendTime.Add(time.Millisecond)
	slowStart.StartReceiveRound(endSendTime)
	for n := 1; n < hybridStartMinSamples; n++ {
		require.False(t, slowStart.ShouldExitSlowStart(rtt+(time.Duration(n)+10)*time.Millisecond, rtt, 100))
	}
	// Expect to trigger since all packets in this burst was above the long term
	// RTT provided.
	require.True(t, slowStart.ShouldExitSlowStart(rtt+10*time.Millisecond, rtt, 100))
}
