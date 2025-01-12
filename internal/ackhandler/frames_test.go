package ackhandler

import (
	"testing"

	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestAckElicitingFrames(t *testing.T) {
	testCases := map[wire.Frame]bool{
		&wire.AckFrame{}:             false,
		&wire.ConnectionCloseFrame{}: false,
		&wire.DataBlockedFrame{}:     true,
		&wire.PingFrame{}:            true,
		&wire.ResetStreamFrame{}:     true,
		&wire.StreamFrame{}:          true,
		&wire.DatagramFrame{}:        true,
		&wire.MaxDataFrame{}:         true,
		&wire.MaxStreamDataFrame{}:   true,
		&wire.StopSendingFrame{}:     true,
		&wire.PathChallengeFrame{}:   true,
		&wire.PathResponseFrame{}:    true,
		&wire.NewConnectionIDFrame{}: true,
	}

	for f, expected := range testCases {
		require.Equal(t, expected, IsFrameAckEliciting(f))
		require.Equal(t, expected, HasAckElicitingFrames([]Frame{{Frame: f}}))
	}

	require.True(t, HasAckElicitingFrames([]Frame{
		{Frame: &wire.AckFrame{}},
		{Frame: &wire.PingFrame{}},
	}))
	require.False(t, HasAckElicitingFrames([]Frame{
		{Frame: &wire.AckFrame{}},
		{Frame: &wire.ConnectionCloseFrame{}},
	}))
}

func TestProbingFrames(t *testing.T) {
	testCases := map[wire.Frame]bool{
		&wire.AckFrame{}:             false,
		&wire.ConnectionCloseFrame{}: false,
		&wire.DataBlockedFrame{}:     false,
		&wire.PingFrame{}:            false,
		&wire.ResetStreamFrame{}:     false,
		&wire.StreamFrame{}:          false,
		&wire.DatagramFrame{}:        false,
		&wire.MaxDataFrame{}:         false,
		&wire.MaxStreamDataFrame{}:   false,
		&wire.StopSendingFrame{}:     false,
		&wire.PathChallengeFrame{}:   true,
		&wire.PathResponseFrame{}:    true,
		&wire.NewConnectionIDFrame{}: true,
	}

	for f, expected := range testCases {
		require.Equal(t, expected, IsProbingFrame(f))
		require.Equal(t, !expected, HasNonProbingFrames([]Frame{{Frame: f}}))
	}

	require.True(t, HasNonProbingFrames([]Frame{
		{Frame: &wire.PathChallengeFrame{}},
		{Frame: &wire.PingFrame{}},
	}))
	require.False(t, HasNonProbingFrames([]Frame{
		{Frame: &wire.PathChallengeFrame{}},
		{Frame: &wire.PathResponseFrame{}},
	}))
}
