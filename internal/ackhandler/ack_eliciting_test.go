package ackhandler

import (
	"testing"

	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestIsFrameTypeAckEliciting(t *testing.T) {
	testCases := map[wire.FrameType]bool{
		wire.PingFrameType:               true,
		wire.AckFrameType:                false,
		wire.AckECNFrameType:             false,
		wire.ResetStreamFrameType:        true,
		wire.StopSendingFrameType:        true,
		wire.CryptoFrameType:             true,
		wire.NewTokenFrameType:           true,
		wire.FrameType(0x08):             true,
		wire.FrameType(0x09):             true,
		wire.FrameType(0x0a):             true,
		wire.FrameType(0x0b):             true,
		wire.FrameType(0x0c):             true,
		wire.FrameType(0x0d):             true,
		wire.FrameType(0x0e):             true,
		wire.FrameType(0x0f):             true,
		wire.MaxDataFrameType:            true,
		wire.MaxStreamDataFrameType:      true,
		wire.BidiMaxStreamsFrameType:     true,
		wire.UniMaxStreamsFrameType:      true,
		wire.DataBlockedFrameType:        true,
		wire.StreamDataBlockedFrameType:  true,
		wire.BidiStreamBlockedFrameType:  true,
		wire.UniStreamBlockedFrameType:   true,
		wire.NewConnectionIDFrameType:    true,
		wire.RetireConnectionIDFrameType: true,
		wire.PathChallengeFrameType:      true,
		wire.PathResponseFrameType:       true,
		wire.ConnectionCloseFrameType:    false,
		wire.ApplicationCloseFrameType:   false,
		wire.HandshakeDoneFrameType:      true,
		wire.ResetStreamAtFrameType:      true,
		wire.DatagramNoLengthFrameType:   true,
		wire.DatagramWithLengthFrameType: true,
	}

	for ft, expected := range testCases {
		require.Equal(t, expected, IsFrameTypeAckEliciting(ft), "unexpected result for frame type 0x%x", ft)
	}
}

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
