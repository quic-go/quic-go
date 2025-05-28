package wire

import (
	"fmt"
	"io"
	"testing"

	"github.com/Noooste/quic-go/internal/protocol"
	"github.com/Noooste/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParseStreamsBlockedFrameBidirectional(t *testing.T) {
	data := encodeVarInt(0x1337)
	f, l, err := parseStreamsBlockedFrame(data, bidiStreamBlockedFrameType, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamTypeBidi, f.Type)
	require.EqualValues(t, 0x1337, f.StreamLimit)
	require.Equal(t, len(data), l)
}

func TestParseStreamsBlockedFrameUnidirectional(t *testing.T) {
	data := encodeVarInt(0x7331)
	f, l, err := parseStreamsBlockedFrame(data, uniStreamBlockedFrameType, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamTypeUni, f.Type)
	require.EqualValues(t, 0x7331, f.StreamLimit)
	require.Equal(t, len(data), l)
}

func TestParseStreamsBlockedFrameErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0x12345678)
	_, l, err := parseStreamsBlockedFrame(data, bidiStreamBlockedFrameType, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parseStreamsBlockedFrame(data[:i], bidiStreamBlockedFrameType, protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestParseStreamsBlockedFrameMaxStreamCount(t *testing.T) {
	for _, streamType := range []protocol.StreamType{protocol.StreamTypeUni, protocol.StreamTypeBidi} {
		var streamTypeStr string
		if streamType == protocol.StreamTypeUni {
			streamTypeStr = "unidirectional"
		} else {
			streamTypeStr = "bidirectional"
		}
		t.Run(streamTypeStr, func(t *testing.T) {
			f := &StreamsBlockedFrame{
				Type:        streamType,
				StreamLimit: protocol.MaxStreamCount,
			}
			b, err := f.Append(nil, protocol.Version1)
			require.NoError(t, err)
			typ, l, err := quicvarint.Parse(b)
			require.NoError(t, err)
			b = b[l:]
			frame, l, err := parseStreamsBlockedFrame(b, typ, protocol.Version1)
			require.NoError(t, err)
			require.Equal(t, f, frame)
			require.Equal(t, len(b), l)
		})
	}
}

func TestParseStreamsBlockedFrameErrorOnTooLargeStreamCount(t *testing.T) {
	for _, streamType := range []protocol.StreamType{protocol.StreamTypeUni, protocol.StreamTypeBidi} {
		var streamTypeStr string
		if streamType == protocol.StreamTypeUni {
			streamTypeStr = "unidirectional"
		} else {
			streamTypeStr = "bidirectional"
		}
		t.Run(streamTypeStr, func(t *testing.T) {
			f := &StreamsBlockedFrame{
				Type:        streamType,
				StreamLimit: protocol.MaxStreamCount + 1,
			}
			b, err := f.Append(nil, protocol.Version1)
			require.NoError(t, err)
			typ, l, err := quicvarint.Parse(b)
			require.NoError(t, err)
			b = b[l:]
			_, _, err = parseStreamsBlockedFrame(b, typ, protocol.Version1)
			require.EqualError(t, err, fmt.Sprintf("%d exceeds the maximum stream count", protocol.MaxStreamCount+1))
		})
	}
}

func TestWriteStreamsBlockedFrameBidirectional(t *testing.T) {
	f := StreamsBlockedFrame{
		Type:        protocol.StreamTypeBidi,
		StreamLimit: 0xdeadbeefcafe,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{bidiStreamBlockedFrameType}
	expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
	require.Equal(t, expected, b)
	require.Equal(t, int(f.Length(protocol.Version1)), len(b))
}

func TestWriteStreamsBlockedFrameUnidirectional(t *testing.T) {
	f := StreamsBlockedFrame{
		Type:        protocol.StreamTypeUni,
		StreamLimit: 0xdeadbeefcafe,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{uniStreamBlockedFrameType}
	expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
	require.Equal(t, expected, b)
	require.Equal(t, int(f.Length(protocol.Version1)), len(b))
}
