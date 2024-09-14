package utils

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestRTTStatsDefaults(t *testing.T) {
	var rttStats RTTStats
	require.Zero(t, rttStats.MinRTT())
	require.Zero(t, rttStats.SmoothedRTT())
}

func TestRTTStatsSmoothedRTT(t *testing.T) {
	var rttStats RTTStats
	// Verify that ack_delay is ignored in the first measurement.
	rttStats.UpdateRTT((300 * time.Millisecond), (100 * time.Millisecond), time.Time{})
	require.Equal(t, (300 * time.Millisecond), rttStats.LatestRTT())
	require.Equal(t, (300 * time.Millisecond), rttStats.SmoothedRTT())
	// Verify that Smoothed RTT includes max ack delay if it's reasonable.
	rttStats.UpdateRTT((350 * time.Millisecond), (50 * time.Millisecond), time.Time{})
	require.Equal(t, (300 * time.Millisecond), rttStats.LatestRTT())
	require.Equal(t, (300 * time.Millisecond), rttStats.SmoothedRTT())
	// Verify that large erroneous ack_delay does not change Smoothed RTT.
	rttStats.UpdateRTT((200 * time.Millisecond), (300 * time.Millisecond), time.Time{})
	require.Equal(t, (200 * time.Millisecond), rttStats.LatestRTT())
	require.Equal(t, (287500 * time.Microsecond), rttStats.SmoothedRTT())
}

func TestRTTStatsMinRTT(t *testing.T) {
	var rttStats RTTStats
	rttStats.UpdateRTT((200 * time.Millisecond), 0, time.Time{})
	require.Equal(t, (200 * time.Millisecond), rttStats.MinRTT())
	rttStats.UpdateRTT((10 * time.Millisecond), 0, time.Time{}.Add((10 * time.Millisecond)))
	require.Equal(t, (10 * time.Millisecond), rttStats.MinRTT())
	rttStats.UpdateRTT((50 * time.Millisecond), 0, time.Time{}.Add((20 * time.Millisecond)))
	require.Equal(t, (10 * time.Millisecond), rttStats.MinRTT())
	rttStats.UpdateRTT((50 * time.Millisecond), 0, time.Time{}.Add((30 * time.Millisecond)))
	require.Equal(t, (10 * time.Millisecond), rttStats.MinRTT())
	rttStats.UpdateRTT((50 * time.Millisecond), 0, time.Time{}.Add((40 * time.Millisecond)))
	require.Equal(t, (10 * time.Millisecond), rttStats.MinRTT())
	// Verify that ack_delay does not go into recording of MinRTT_.
	rttStats.UpdateRTT((7 * time.Millisecond), (2 * time.Millisecond), time.Time{}.Add((50 * time.Millisecond)))
	require.Equal(t, (7 * time.Millisecond), rttStats.MinRTT())
}

func TestRTTStatsMaxAckDelay(t *testing.T) {
	var rttStats RTTStats
	rttStats.SetMaxAckDelay(42 * time.Minute)
	require.Equal(t, 42*time.Minute, rttStats.MaxAckDelay())
}

func TestRTTStatsComputePTO(t *testing.T) {
	const (
		maxAckDelay = 42 * time.Minute
		rtt         = time.Second
	)
	var rttStats RTTStats
	rttStats.SetMaxAckDelay(maxAckDelay)
	rttStats.UpdateRTT(rtt, 0, time.Time{})
	require.Equal(t, rtt, rttStats.SmoothedRTT())
	require.Equal(t, rtt/2, rttStats.MeanDeviation())
	require.Equal(t, rtt+4*(rtt/2), rttStats.PTO(false))
	require.Equal(t, rtt+4*(rtt/2)+maxAckDelay, rttStats.PTO(true))
}

func TestRTTStatsPTOWithShortRTT(t *testing.T) {
	const rtt = time.Microsecond
	var rttStats RTTStats
	rttStats.UpdateRTT(rtt, 0, time.Time{})
	require.Equal(t, rtt+protocol.TimerGranularity, rttStats.PTO(true))
}

func TestRTTStatsUpdateWithBadSendDeltas(t *testing.T) {
	var rttStats RTTStats
	const initialRtt = 10 * time.Millisecond
	rttStats.UpdateRTT(initialRtt, 0, time.Time{})
	require.Equal(t, initialRtt, rttStats.MinRTT())
	require.Equal(t, initialRtt, rttStats.SmoothedRTT())

	badSendDeltas := []time.Duration{
		0,
		-1000 * time.Microsecond,
	}

	for _, badSendDelta := range badSendDeltas {
		rttStats.UpdateRTT(badSendDelta, 0, time.Time{})
		require.Equal(t, initialRtt, rttStats.MinRTT())
		require.Equal(t, initialRtt, rttStats.SmoothedRTT())
	}
}

func TestRTTStatsRestore(t *testing.T) {
	var rttStats RTTStats
	rttStats.SetInitialRTT(10 * time.Second)
	require.Equal(t, 10*time.Second, rttStats.LatestRTT())
	require.Equal(t, 10*time.Second, rttStats.SmoothedRTT())
	require.Zero(t, rttStats.MeanDeviation())
	// update the RTT and make sure that the initial value is immediately forgotten
	rttStats.UpdateRTT(200*time.Millisecond, 0, time.Time{})
	require.Equal(t, 200*time.Millisecond, rttStats.LatestRTT())
	require.Equal(t, 200*time.Millisecond, rttStats.SmoothedRTT())
	require.Equal(t, 100*time.Millisecond, rttStats.MeanDeviation())
}

func TestRTTMeasurementAfterRestore(t *testing.T) {
	var rttStats RTTStats
	const rtt = 10 * time.Millisecond
	rttStats.UpdateRTT(rtt, 0, time.Now())
	require.Equal(t, rtt, rttStats.LatestRTT())
	require.Equal(t, rtt, rttStats.SmoothedRTT())
	rttStats.SetInitialRTT(time.Minute)
	require.Equal(t, rtt, rttStats.LatestRTT())
	require.Equal(t, rtt, rttStats.SmoothedRTT())
}
