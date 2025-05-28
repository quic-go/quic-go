package logging_test

import (
	"testing"

	"github.com/Noooste/quic-go/internal/protocol"
	"github.com/Noooste/quic-go/internal/wire"
	"github.com/Noooste/quic-go/logging"
	"github.com/stretchr/testify/require"
)

func TestPacketTypeFromHeader(t *testing.T) {
	testCases := []struct {
		name         string
		header       *wire.Header
		expectedType logging.PacketType
	}{
		{
			name: "Initial packet",
			header: &wire.Header{
				Type:    protocol.PacketTypeInitial,
				Version: protocol.Version1,
			},
			expectedType: logging.PacketTypeInitial,
		},
		{
			name: "Handshake packet",
			header: &wire.Header{
				Type:    protocol.PacketTypeHandshake,
				Version: protocol.Version1,
			},
			expectedType: logging.PacketTypeHandshake,
		},
		{
			name: "Retry packet",
			header: &wire.Header{
				Type:    protocol.PacketTypeRetry,
				Version: protocol.Version1,
			},
			expectedType: logging.PacketTypeRetry,
		},
		{
			name: "0-RTT packet",
			header: &wire.Header{
				Type:    protocol.PacketType0RTT,
				Version: protocol.Version1,
			},
			expectedType: logging.PacketType0RTT,
		},
		{
			name:         "Version Negotiation packet",
			header:       &wire.Header{},
			expectedType: logging.PacketTypeVersionNegotiation,
		},
		{
			name: "Unrecognized packet type",
			header: &wire.Header{
				Version: protocol.Version1,
			},
			expectedType: logging.PacketTypeNotDetermined,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			packetType := logging.PacketTypeFromHeader(tc.header)
			require.Equal(t, tc.expectedType, packetType)
		})
	}
}
