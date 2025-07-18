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

func TestIsProbingFrameType(t *testing.T) {
	tests := map[FrameType]bool{
		FrameTypePathChallenge:   true,
		FrameTypePathResponse:    true,
		FrameTypeNewConnectionID: true,
		FrameType(0x01):          false,
		FrameType(0xFF):          false,
	}
	for ft, expected := range tests {
		require.Equal(t, expected, IsProbingFrameType(ft))
	}
}
