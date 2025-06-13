package wire

import (
	"io"
	"testing"

	"github.com/Noooste/uquic-go/internal/protocol"
	"github.com/Noooste/uquic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParseDataBlocked(t *testing.T) {
	data := encodeVarInt(0x12345678)
	frame, l, err := parseDataBlockedFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(0x12345678), frame.MaximumData)
	require.Equal(t, len(data), l)
}

func TestParseDataBlockedErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0x12345678)
	_, l, err := parseDataBlockedFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parseDataBlockedFrame(data[:i], protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestWriteDataBlocked(t *testing.T) {
	frame := DataBlockedFrame{MaximumData: 0xdeadbeef}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{dataBlockedFrameType}
	expected = append(expected, encodeVarInt(0xdeadbeef)...)
	require.Equal(t, expected, b)
	require.Equal(t, protocol.ByteCount(1+quicvarint.Len(uint64(frame.MaximumData))), frame.Length(protocol.Version1))
}
