package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLongHeaderPacketTypeStringer(t *testing.T) {
	require.Equal(t, "Initial", PacketTypeInitial.String())
	require.Equal(t, "Retry", PacketTypeRetry.String())
	require.Equal(t, "Handshake", PacketTypeHandshake.String())
	require.Equal(t, "0-RTT Protected", PacketType0RTT.String())
	require.Equal(t, "unknown packet type: 10", PacketType(10).String())
}

func TestECNFromIPHeader(t *testing.T) {
	require.Equal(t, ECNNon, ParseECNHeaderBits(0))
	require.Equal(t, ECT0, ParseECNHeaderBits(0b00000010))
	require.Equal(t, ECT1, ParseECNHeaderBits(0b00000001))
	require.Equal(t, ECNCE, ParseECNHeaderBits(0b00000011))
	require.Panics(t, func() { ParseECNHeaderBits(0b1010101) })
}

func TestECNConversionToIPHeaderBits(t *testing.T) {
	for _, v := range [...]ECN{ECNNon, ECT0, ECT1, ECNCE} {
		require.Equal(t, v, ParseECNHeaderBits(v.ToHeaderBits()))
	}
	require.Panics(t, func() { ECN(42).ToHeaderBits() })
}

func TestECNStringer(t *testing.T) {
	require.Equal(t, "ECN unsupported", ECNUnsupported.String())
	require.Equal(t, "Not-ECT", ECNNon.String())
	require.Equal(t, "ECT(0)", ECT0.String())
	require.Equal(t, "ECT(1)", ECT1.String())
	require.Equal(t, "CE", ECNCE.String())
	require.Equal(t, "invalid ECN value: 42", ECN(42).String())
}
