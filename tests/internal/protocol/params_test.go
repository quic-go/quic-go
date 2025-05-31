package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPacketQueueCapacities(t *testing.T) {
	// Ensure that the session can queue more packets than the 0-RTT queue
	require.Greater(t, MaxConnUnprocessedPackets, Max0RTTQueueLen)
	require.Greater(t, MaxUndecryptablePackets, Max0RTTQueueLen)
}
