package qlog

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestEncryptionLevelToPacketType(t *testing.T) {
	require.Equal(t, "initial", string(EncryptionLevelToPacketType(protocol.EncryptionInitial)))
	require.Equal(t, "handshake", string(EncryptionLevelToPacketType(protocol.EncryptionHandshake)))
	require.Equal(t, "0RTT", string(EncryptionLevelToPacketType(protocol.Encryption0RTT)))
	require.Equal(t, "1RTT", string(EncryptionLevelToPacketType(protocol.Encryption1RTT)))
}
