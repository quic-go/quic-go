package wire

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
)

func TestNewFrameType_ValidTypes(t *testing.T) {
	tests := []struct {
		input    uint64
		expected FrameType
	}{
		{0x1, PingFrameType},
		{0x2, AckFrameType},
		{0x3, AckECNFrameType},
		{0x4, ResetStreamFrameType},
		{0x5, StopSendingFrameType},
		{0x6, CryptoFrameType},
		{0x7, NewTokenFrameType},
		{0x10, MaxDataFrameType},
		{0x11, MaxStreamDataFrameType},
		{0x12, BidiMaxStreamsFrameType},
		{0x13, UniMaxStreamsFrameType},
		{0x14, DataBlockedFrameType},
		{0x15, StreamDataBlockedFrameType},
		{0x16, BidiStreamBlockedFrameType},
		{0x17, UniStreamBlockedFrameType},
		{0x18, NewConnectionIDFrameType},
		{0x19, RetireConnectionIDFrameType},
		{0x1a, PathChallengeFrameType},
		{0x1b, PathResponseFrameType},
		{0x1c, ConnectionCloseFrameType},
		{0x1d, ApplicationCloseFrameType},
		{0x1e, HandshakeDoneFrameType},
		{0x24, ResetStreamAtFrameType},
		{0x30, DatagramNoLengthFrameType},
		{0x31, DatagramWithLengthFrameType},
	}

	for _, tt := range tests {
		ft, ok := NewFrameType(tt.input)
		if !ok {
			t.Errorf("NewFrameType(%#x) expected ok=true", tt.input)
		}
		if ft != tt.expected {
			t.Errorf("NewFrameType(%#x) = %v, want %v", tt.input, ft, tt.expected)
		}
	}
}

func TestIsStreamFrameType(t *testing.T) {
	for i := 0x08; i <= 0x0f; i++ {
		if !FrameType(i).IsStreamFrameType() {
			t.Errorf("FrameType(0x%x).IsStreamFrameType() = false, want true", i)
		}
	}

	if FrameType(0x1).IsStreamFrameType() {
		t.Errorf("FrameType(0x1).IsStreamFrameType() = true, want false")
	}
}

func TestIsAllowedAtEncLevel(t *testing.T) {
	type testCase struct {
		ft              FrameType
		level           protocol.EncryptionLevel
		shouldBeAllowed bool
	}

	tests := []testCase{
		{PingFrameType, protocol.EncryptionInitial, true},
		{CryptoFrameType, protocol.EncryptionInitial, true},
		{NewTokenFrameType, protocol.EncryptionInitial, false},

		{NewTokenFrameType, protocol.Encryption0RTT, false},
		{DatagramWithLengthFrameType, protocol.Encryption0RTT, true},

		{RetireConnectionIDFrameType, protocol.Encryption0RTT, false},
		{PathChallengeFrameType, protocol.Encryption0RTT, true},

		{MaxDataFrameType, protocol.Encryption1RTT, true},
		{PingFrameType, protocol.Encryption1RTT, true},
	}

	for _, tc := range tests {
		allowed := tc.ft.isAllowedAtEncLevel(tc.level)
		if allowed != tc.shouldBeAllowed {
			t.Errorf("FrameType %v at level %v: expected allowed=%v, got %v", tc.ft, tc.level, tc.shouldBeAllowed, allowed)
		}
	}
}

func TestIsAllowedAtEncLevel_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for unknown encryption level")
		}
	}()

	var unknownLevel protocol.EncryptionLevel = 255
	_ = PingFrameType.isAllowedAtEncLevel(unknownLevel)
}
