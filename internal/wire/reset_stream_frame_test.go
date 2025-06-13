package wire

import (
	"testing"

	"github.com/Noooste/uquic-go/internal/protocol"
	"github.com/Noooste/uquic-go/internal/qerr"

	"github.com/stretchr/testify/require"
)

func TestParseResetStream(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)                  // stream ID
	data = append(data, encodeVarInt(0x1337)...)      // error code
	data = append(data, encodeVarInt(0x987654321)...) // byte offset
	frame, l, err := parseResetStreamFrame(data, false, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamID(0xdeadbeef), frame.StreamID)
	require.Equal(t, protocol.ByteCount(0x987654321), frame.FinalSize)
	require.Equal(t, qerr.StreamErrorCode(0x1337), frame.ErrorCode)
	require.Equal(t, len(data), l)
}

func TestParseResetStreamAt(t *testing.T) {
	data := encodeVarInt(0xabcdef12)                  // stream ID
	data = append(data, encodeVarInt(0x2468)...)      // error code
	data = append(data, encodeVarInt(0x123456789)...) // byte offset
	data = append(data, encodeVarInt(0x789abc)...)    // reliable size
	frame, l, err := parseResetStreamFrame(data, true, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamID(0xabcdef12), frame.StreamID)
	require.Equal(t, protocol.ByteCount(0x123456789), frame.FinalSize)
	require.Equal(t, qerr.StreamErrorCode(0x2468), frame.ErrorCode)
	require.Equal(t, protocol.ByteCount(0x789abc), frame.ReliableSize)
	require.Equal(t, len(data), l)
}

func TestParseResetStreamAtSizeTooLarge(t *testing.T) {
	data := encodeVarInt(0xabcdef12)             // stream ID
	data = append(data, encodeVarInt(0x2468)...) // error code
	data = append(data, encodeVarInt(1000)...)   // byte offset
	data = append(data, encodeVarInt(1001)...)   // reliable size
	_, _, err := parseResetStreamFrame(data, true, protocol.Version1)
	require.EqualError(t, err, "RESET_STREAM_AT: reliable size can't be larger than final size (1001 vs 1000)")
}

func TestParseResetStreamErrorsOnEOFs(t *testing.T) {
	t.Run("RESET_STREAM", func(t *testing.T) {
		testParseResetStreamErrorsOnEOFs(t, false)
	})
	t.Run("RESET_STREAM_AT", func(t *testing.T) {
		testParseResetStreamErrorsOnEOFs(t, true)
	})
}

func testParseResetStreamErrorsOnEOFs(t *testing.T, isResetStreamAt bool) {
	data := encodeVarInt(0xdeadbeef)                  // stream ID
	data = append(data, encodeVarInt(0x1337)...)      // error code
	data = append(data, encodeVarInt(0x987654321)...) // byte offset
	if isResetStreamAt {
		data = append(data, encodeVarInt(0x123456)...) // reliable size
	}
	_, l, err := parseResetStreamFrame(data, isResetStreamAt, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parseResetStreamFrame(data[:i], isResetStreamAt, protocol.Version1)
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

func TestWriteResetStreamAt(t *testing.T) {
	frame := ResetStreamFrame{
		StreamID:     1337,
		FinalSize:    42,
		ErrorCode:    0xcafe,
		ReliableSize: 12,
	}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{resetStreamAtFrameType}
	expected = append(expected, encodeVarInt(1337)...)
	expected = append(expected, encodeVarInt(0xcafe)...)
	expected = append(expected, encodeVarInt(42)...)
	expected = append(expected, encodeVarInt(12)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(frame.Length(protocol.Version1)))
}
