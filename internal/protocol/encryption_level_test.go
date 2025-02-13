package protocol

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptionLevelNonZeroValue(t *testing.T) {
	require.NotZero(t, EncryptionInitial*EncryptionHandshake*Encryption0RTT*Encryption1RTT)
}

func TestEncryptionLevelConversion(t *testing.T) {
	testCases := []struct {
		quicLevel EncryptionLevel
		tlsLevel  tls.QUICEncryptionLevel
	}{
		{EncryptionInitial, tls.QUICEncryptionLevelInitial},
		{EncryptionHandshake, tls.QUICEncryptionLevelHandshake},
		{Encryption1RTT, tls.QUICEncryptionLevelApplication},
		{Encryption0RTT, tls.QUICEncryptionLevelEarly},
	}

	for _, tc := range testCases {
		t.Run(tc.quicLevel.String(), func(t *testing.T) {
			// conversion from QUIC to TLS encryption level
			require.Equal(t, tc.tlsLevel, tc.quicLevel.ToTLSEncryptionLevel())
			// conversion from TLS to QUIC encryption level
			require.Equal(t, tc.quicLevel, FromTLSEncryptionLevel(tc.tlsLevel))
		})
	}
}

func TestEncryptionLevelStringRepresentation(t *testing.T) {
	require.Equal(t, "Initial", EncryptionInitial.String())
	require.Equal(t, "Handshake", EncryptionHandshake.String())
	require.Equal(t, "0-RTT", Encryption0RTT.String())
	require.Equal(t, "1-RTT", Encryption1RTT.String())
}
