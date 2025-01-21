package wire

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProbingFrames(t *testing.T) {
	testCases := map[Frame]bool{
		&AckFrame{}:             false,
		&ConnectionCloseFrame{}: false,
		&DataBlockedFrame{}:     false,
		&PingFrame{}:            false,
		&ResetStreamFrame{}:     false,
		&StreamFrame{}:          false,
		&DatagramFrame{}:        false,
		&MaxDataFrame{}:         false,
		&MaxStreamDataFrame{}:   false,
		&StopSendingFrame{}:     false,
		&PathChallengeFrame{}:   true,
		&PathResponseFrame{}:    true,
		&NewConnectionIDFrame{}: true,
	}

	for f, expected := range testCases {
		require.Equal(t, expected, IsProbingFrame(f))
	}
}
