package ackhandler

import (
	"testing"

	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestIsFrameTypeAckEliciting(t *testing.T) {
	testCases := map[wire.FrameType]bool{
		wire.FrameTypePing:               true,
		wire.FrameTypeAck:                false,
		wire.FrameTypeAckECN:             false,
		wire.FrameTypeResetStream:        true,
		wire.FrameTypeStopSending:        true,
		wire.FrameTypeCrypto:             true,
		wire.FrameTypeNewToken:           true,
		wire.FrameType(0x08):             true,
		wire.FrameType(0x09):             true,
		wire.FrameType(0x0a):             true,
		wire.FrameType(0x0b):             true,
		wire.FrameType(0x0c):             true,
		wire.FrameType(0x0d):             true,
		wire.FrameType(0x0e):             true,
		wire.FrameType(0x0f):             true,
		wire.FrameTypeMaxData:            true,
		wire.FrameTypeMaxStreamData:      true,
		wire.FrameTypeBidiMaxStreams:     true,
		wire.FrameTypeUniMaxStreams:      true,
		wire.FrameTypeDataBlocked:        true,
		wire.FrameTypeStreamDataBlocked:  true,
		wire.FrameTypeBidiStreamBlocked:  true,
		wire.FrameTypeUniStreamBlocked:   true,
		wire.FrameTypeNewConnectionID:    true,
		wire.FrameTypeRetireConnectionID: true,
		wire.FrameTypePathChallenge:      true,
		wire.FrameTypePathResponse:       true,
		wire.FrameTypeConnectionClose:    false,
		wire.FrameTypeApplicationClose:   false,
		wire.FrameTypeHandshakeDone:      true,
		wire.FrameTypeResetStreamAt:      true,
		wire.FrameTypeDatagramNoLength:   true,
		wire.FrameTypeDatagramWithLength: true,
		wire.FrameTypeAckFrequency:       true,
		wire.FrameTypeImmediateAck:       true,
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
		&wire.AckFrequencyFrame{}:    true,
		&wire.ImmediateAckFrame{}:    true,
	}

	for f, expected := range testCases {
		require.Equal(t, expected, IsFrameAckEliciting(f))
		require.Equal(t, expected, HasAckElicitingFrames([]Frame{{Frame: f}}))
	}
}
