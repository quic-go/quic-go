package wire

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"

	"github.com/stretchr/testify/require"
)

func TestParseResetStream(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)                  // stream ID
	data = append(data, encodeVarInt(0x1337)...)      // error code
	data = append(data, encodeVarInt(0x987654321)...) // byte offset
	frame, l, err := parseResetStreamFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamID(0xdeadbeef), frame.StreamID)
	require.Equal(t, protocol.ByteCount(0x987654321), frame.FinalSize)
	require.Equal(t, qerr.StreamErrorCode(0x1337), frame.ErrorCode)
	require.Equal(t, len(data), l)
}

func TestParseResetStreamErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)                  // stream ID
	data = append(data, encodeVarInt(0x1337)...)      // error code
	data = append(data, encodeVarInt(0x987654321)...) // byte offset
	_, l, err := parseResetStreamFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parseResetStreamFrame(data[:i], protocol.Version1)
		require.Error(t, err)
	}
}

func TestWriteResetStream(t *testing.T) {
	frame := ResetStreamFrame{
		StreamID:  0x1337,
		FinalSize: 0x11223344decafbad,
		ErrorCode: 0xcafe,
	}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{resetStreamFrameType}
	expected = append(expected, encodeVarInt(0x1337)...)
	expected = append(expected, encodeVarInt(0xcafe)...)
	expected = append(expected, encodeVarInt(0x11223344decafbad)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(frame.Length(protocol.Version1)))
}
