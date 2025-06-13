package wire

import (
	"fmt"
	"io"
	"testing"

	"github.com/Noooste/uquic-go/internal/protocol"
	"github.com/Noooste/uquic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParseMaxStreamsFrameBidirectional(t *testing.T) {
	data := encodeVarInt(0xdecaf)
	f, l, err := parseMaxStreamsFrame(data, bidiMaxStreamsFrameType, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamTypeBidi, f.Type)
	require.EqualValues(t, 0xdecaf, f.MaxStreamNum)
	require.Equal(t, len(data), l)
}

func TestParseMaxStreamsFrameUnidirectional(t *testing.T) {
	data := encodeVarInt(0xdecaf)
	f, l, err := parseMaxStreamsFrame(data, uniMaxStreamsFrameType, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamTypeUni, f.Type)
	require.EqualValues(t, 0xdecaf, f.MaxStreamNum)
	require.Equal(t, len(data), l)
}

func TestParseMaxStreamsErrorsOnEOF(t *testing.T) {
	const typ = 0x1d
	data := encodeVarInt(0xdeadbeefcafe13)
	_, l, err := parseMaxStreamsFrame(data, typ, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parseMaxStreamsFrame(data[:i], typ, protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestParseMaxStreamsMaxValue(t *testing.T) {
	for _, streamType := range []protocol.StreamType{protocol.StreamTypeUni, protocol.StreamTypeBidi} {
		var streamTypeStr string
		if streamType == protocol.StreamTypeUni {
			streamTypeStr = "unidirectional"
		} else {
			streamTypeStr = "bidirectional"
		}
		t.Run(streamTypeStr, func(t *testing.T) {
			f := &MaxStreamsFrame{
				Type:         streamType,
				MaxStreamNum: protocol.MaxStreamCount,
			}
			b, err := f.Append(nil, protocol.Version1)
			require.NoError(t, err)
			typ, l, err := quicvarint.Parse(b)
			require.NoError(t, err)
			b = b[l:]
			frame, _, err := parseMaxStreamsFrame(b, typ, protocol.Version1)
			require.NoError(t, err)
			require.Equal(t, f, frame)
		})
	}
}

func TestParseMaxStreamsErrorsOnTooLargeStreamCount(t *testing.T) {
	for _, streamType := range []protocol.StreamType{protocol.StreamTypeUni, protocol.StreamTypeBidi} {
		var streamTypeStr string
		if streamType == protocol.StreamTypeUni {
			streamTypeStr = "unidirectional"
		} else {
			streamTypeStr = "bidirectional"
		}
		t.Run(streamTypeStr, func(t *testing.T) {
			f := &MaxStreamsFrame{
				Type:         streamType,
				MaxStreamNum: protocol.MaxStreamCount + 1,
			}
			b, err := f.Append(nil, protocol.Version1)
			require.NoError(t, err)
			typ, l, err := quicvarint.Parse(b)
			require.NoError(t, err)
			b = b[l:]
			_, _, err = parseMaxStreamsFrame(b, typ, protocol.Version1)
			require.EqualError(t, err, fmt.Sprintf("%d exceeds the maximum stream count", protocol.MaxStreamCount+1))
		})
	}
}

func TestWriteMaxStreamsBidirectional(t *testing.T) {
	f := &MaxStreamsFrame{
		Type:         protocol.StreamTypeBidi,
		MaxStreamNum: 0xdeadbeef,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{bidiMaxStreamsFrameType}
	expected = append(expected, encodeVarInt(0xdeadbeef)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(f.Length(protocol.Version1)))
}

func TestWriteMaxStreamsUnidirectional(t *testing.T) {
	f := &MaxStreamsFrame{
		Type:         protocol.StreamTypeUni,
		MaxStreamNum: 0xdecafbad,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{uniMaxStreamsFrameType}
	expected = append(expected, encodeVarInt(0xdecafbad)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(f.Length(protocol.Version1)))
}
