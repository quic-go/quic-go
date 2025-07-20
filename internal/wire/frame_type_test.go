package wire

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsStreamFrameType(t *testing.T) {
	for i := 0x08; i <= 0x0f; i++ {
		require.Truef(t, FrameType(i).IsStreamFrameType(), "FrameType(0x%x).IsStreamFrameType() = false, want true", i)
	}

	require.False(t, FrameType(0x1).IsStreamFrameType())
}

func TestIsAckFrameType(t *testing.T) {
	require.True(t, FrameTypeAck.IsAckFrameType(), "AckFrameType should be recognized as ACK")
	require.True(t, FrameTypeAckECN.IsAckFrameType(), "AckECNFrameType should be recognized as ACK")
	require.False(t, FrameTypePing.IsAckFrameType(), "PingFrameType should not be recognized as ACK")
	require.False(t, FrameType(0x10).IsAckFrameType(), "MaxDataFrameType should not be recognized as ACK")
}

func TestIsDatagramFrameType(t *testing.T) {
	require.True(t, FrameTypeDatagramNoLength.IsDatagramFrameType(), "DatagramNoLengthFrameType should be recognized as DATAGRAM")
	require.True(t, FrameTypeDatagramWithLength.IsDatagramFrameType(), "DatagramWithLengthFrameType should be recognized as DATAGRAM")
	require.False(t, FrameTypePing.IsDatagramFrameType(), "PingFrameType should not be recognized as DATAGRAM")
	require.False(t, FrameType(0x1e).IsDatagramFrameType(), "HandshakeDoneFrameType should not be recognized as DATAGRAM")
}
