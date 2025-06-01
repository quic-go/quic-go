package congestion

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBandwidthFromDelta(t *testing.T) {
	require.Equal(t, 1000*BytesPerSecond, BandwidthFromDelta(1, time.Millisecond))
}
