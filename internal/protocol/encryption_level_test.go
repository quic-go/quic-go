package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptionLevelNonZeroValue(t *testing.T) {
	require.NotZero(t, EncryptionInitial*EncryptionHandshake*Encryption0RTT*Encryption1RTT)
}

func TestEncryptionLevelStringRepresentation(t *testing.T) {
	require.Equal(t, "Initial", EncryptionInitial.String())
	require.Equal(t, "Handshake", EncryptionHandshake.String())
	require.Equal(t, "0-RTT", Encryption0RTT.String())
	require.Equal(t, "1-RTT", Encryption1RTT.String())
}
