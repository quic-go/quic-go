package wire

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestQXPingFrame(t *testing.T) {
	for _, isResponse := range []bool{false, true} {
		f := &QXPingFrame{SequenceNumber: 0xdecafbad, IsResponse: isResponse}
		b, err := f.Append(nil, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, f.Length(protocol.Version1), protocol.ByteCount(len(b)))

		expectedType := FrameTypeQXPingRequest
		if isResponse {
			expectedType = FrameTypeQXPingResponse
		}

		parser := NewFrameParser(true, true, true)
		parser.SetSupportsQMux(true)
		frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
		require.NoError(t, err)
		require.Equal(t, expectedType, frameType)
		require.Equal(t, quicvarint.Len(uint64(expectedType)), l)

		parsed, n, err := parser.ParseLessCommonFrame(frameType, b[l:], protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, f, parsed)
		require.Equal(t, len(b)-l, n)
	}
}

func TestQXTransportParametersFrame(t *testing.T) {
	f := &QXTransportParametersFrame{TransportParameters: []byte("transport-parameters")}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f.Length(protocol.Version1), protocol.ByteCount(len(b)))

	parser := NewFrameParser(true, true, true)
	parser.SetSupportsQMux(true)
	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypeQXTransportParametersFrame, frameType)
	require.Equal(t, quicvarint.Len(uint64(FrameTypeQXTransportParametersFrame)), l)

	parsed, n, err := parser.ParseLessCommonFrame(frameType, b[l:], protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, parsed)
	require.Equal(t, len(b)-l, n)
}

func TestFrameParserQMuxUnsupported(t *testing.T) {
	f := &QXPingFrame{SequenceNumber: 1}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)

	parser := NewFrameParser(true, true, true)
	_, _, err = parser.ParseType(b, protocol.Encryption1RTT)
	checkFrameUnsupported(t, err, uint64(FrameTypeQXPingRequest))
}
