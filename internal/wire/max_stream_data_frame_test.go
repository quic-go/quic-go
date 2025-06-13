package wire

import (
	"io"
	"testing"

	"github.com/Noooste/uquic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParseMaxStreamFrame(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)                 // Stream ID
	data = append(data, encodeVarInt(0x12345678)...) // Offset
	frame, l, err := parseMaxStreamDataFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamID(0xdeadbeef), frame.StreamID)
	require.Equal(t, protocol.ByteCount(0x12345678), frame.MaximumStreamData)
	require.Equal(t, len(data), l)
}

func TestParseMaxStreamDataErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)                 // Stream ID
	data = append(data, encodeVarInt(0x12345678)...) // Offset
	_, l, err := parseMaxStreamDataFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parseMaxStreamDataFrame(data[:i], protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestWriteMaxStreamDataFrame(t *testing.T) {
	f := &MaxStreamDataFrame{
		StreamID:          0xdecafbad,
		MaximumStreamData: 0xdeadbeefcafe42,
	}
	expected := []byte{maxStreamDataFrameType}
	expected = append(expected, encodeVarInt(0xdecafbad)...)
	expected = append(expected, encodeVarInt(0xdeadbeefcafe42)...)
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, expected, b)
	require.Equal(t, len(b), int(f.Length(protocol.Version1)))
}
