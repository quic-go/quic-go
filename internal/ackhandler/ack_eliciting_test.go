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
	}

	for f, expected := range testCases {
		require.Equal(t, expected, IsFrameAckEliciting(f))
		require.Equal(t, expected, HasAckElicitingFrames([]Frame{{Frame: f}}))
	}
}
