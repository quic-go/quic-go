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
	tests := []struct {
		name     string
		input    FrameType
		expected bool
	}{
		{
			name:     "PathChallengeFrameType is probing",
			input:    PathChallengeFrameType,
			expected: true,
		},
		{
			name:     "PathResponseFrameType is probing",
			input:    PathResponseFrameType,
			expected: true,
		},
		{
			name:     "NewConnectionIDFrameType is probing",
			input:    NewConnectionIDFrameType,
			expected: true,
		},
		{
			name:     "Non-probing frame type (e.g., 0x01)",
			input:    FrameType(0x01),
			expected: false,
		},
		{
			name:     "Non-probing frame type (e.g., 0xFF)",
			input:    FrameType(0xFF),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, IsProbingFrameType(tt.input))
		})
	}
}
