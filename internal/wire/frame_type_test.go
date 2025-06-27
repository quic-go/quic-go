package wire

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
)

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
