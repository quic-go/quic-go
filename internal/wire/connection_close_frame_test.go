package wire

import (
	"io"
	"testing"

	"github.com/Noooste/uquic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParseConnectionCloseTransportError(t *testing.T) {
	reason := "No recent network activity."
	data := encodeVarInt(0x19)
	data = append(data, encodeVarInt(0x1337)...)              // frame type
	data = append(data, encodeVarInt(uint64(len(reason)))...) // reason phrase length
	data = append(data, []byte(reason)...)
	frame, l, err := parseConnectionCloseFrame(data, connectionCloseFrameType, protocol.Version1)
	require.NoError(t, err)
	require.False(t, frame.IsApplicationError)
	require.EqualValues(t, 0x19, frame.ErrorCode)
	require.EqualValues(t, 0x1337, frame.FrameType)
	require.Equal(t, reason, frame.ReasonPhrase)
	require.Equal(t, len(data), l)
}

func TestParseConnectionCloseWithApplicationError(t *testing.T) {
	reason := "The application messed things up."
	data := encodeVarInt(0xcafe)
	data = append(data, encodeVarInt(uint64(len(reason)))...) // reason phrase length
	data = append(data, reason...)
	frame, l, err := parseConnectionCloseFrame(data, applicationCloseFrameType, protocol.Version1)
	require.NoError(t, err)
	require.True(t, frame.IsApplicationError)
	require.EqualValues(t, 0xcafe, frame.ErrorCode)
	require.Equal(t, reason, frame.ReasonPhrase)
	require.Equal(t, len(data), l)
}

func TestParseConnectionCloseLongReasonPhrase(t *testing.T) {
	data := encodeVarInt(0xcafe)
	data = append(data, encodeVarInt(0x42)...)   // frame type
	data = append(data, encodeVarInt(0xffff)...) // reason phrase length
	_, _, err := parseConnectionCloseFrame(data, connectionCloseFrameType, protocol.Version1)
	require.Equal(t, io.EOF, err)
}

func TestParseConnectionCloseErrorsOnEOFs(t *testing.T) {
	reason := "No recent network activity."
	data := encodeVarInt(0x19)
	data = append(data, encodeVarInt(0x1337)...)              // frame type
	data = append(data, encodeVarInt(uint64(len(reason)))...) // reason phrase length
	data = append(data, []byte(reason)...)
	_, l, err := parseConnectionCloseFrame(data, connectionCloseFrameType, protocol.Version1)
	require.Equal(t, len(data), l)
	require.NoError(t, err)
	for i := range data {
		_, _, err = parseConnectionCloseFrame(data[:i], connectionCloseFrameType, protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestParseConnectionCloseNoReasonPhrase(t *testing.T) {
	data := encodeVarInt(0xcafe)
	data = append(data, encodeVarInt(0x42)...) // frame type
	data = append(data, encodeVarInt(0)...)
	frame, l, err := parseConnectionCloseFrame(data, connectionCloseFrameType, protocol.Version1)
	require.NoError(t, err)
	require.Empty(t, frame.ReasonPhrase)
	require.Equal(t, len(data), l)
}

func TestWriteConnectionCloseNoReasonPhrase(t *testing.T) {
	frame := &ConnectionCloseFrame{
		ErrorCode: 0xbeef,
		FrameType: 0x12345,
	}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{connectionCloseFrameType}
	expected = append(expected, encodeVarInt(0xbeef)...)
	expected = append(expected, encodeVarInt(0x12345)...) // frame type
	expected = append(expected, encodeVarInt(0)...)       // reason phrase length
	require.Equal(t, expected, b)
}

func TestWriteConnectionCloseWithReasonPhrase(t *testing.T) {
	frame := &ConnectionCloseFrame{
		ErrorCode:    0xdead,
		ReasonPhrase: "foobar",
	}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{connectionCloseFrameType}
	expected = append(expected, encodeVarInt(0xdead)...)
	expected = append(expected, encodeVarInt(0)...) // frame type
	expected = append(expected, encodeVarInt(6)...) // reason phrase length
	expected = append(expected, []byte("foobar")...)
	require.Equal(t, expected, b)
}

func TestWriteConnectionCloseWithApplicationError(t *testing.T) {
	frame := &ConnectionCloseFrame{
		IsApplicationError: true,
		ErrorCode:          0xdead,
		ReasonPhrase:       "foobar",
	}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{applicationCloseFrameType}
	expected = append(expected, encodeVarInt(0xdead)...)
	expected = append(expected, encodeVarInt(6)...) // reason phrase length
	expected = append(expected, []byte("foobar")...)
	require.Equal(t, expected, b)
}

func TestWriteConnectionCloseTransportError(t *testing.T) {
	f := &ConnectionCloseFrame{
		ErrorCode:    0xcafe,
		FrameType:    0xdeadbeef,
		ReasonPhrase: "foobar",
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, b, int(f.Length(protocol.Version1)))
}

func TestWriteConnectionCloseLength(t *testing.T) {
	f := &ConnectionCloseFrame{
		IsApplicationError: true,
		ErrorCode:          0xcafe,
		ReasonPhrase:       "foobar",
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, b, int(f.Length(protocol.Version1)))
}
