package wire

import (
	"io"
	"math"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParseAckFrequency(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)             // sequence number
	data = append(data, encodeVarInt(0xcafe)...) // threshold
	data = append(data, encodeVarInt(1337)...)   // update max ack delay
	data = append(data, encodeVarInt(12345)...)  // reordering threshold
	frame, l, err := parseAckFrequencyFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, uint64(0xdeadbeef), frame.SequenceNumber)
	require.Equal(t, uint64(0xcafe), frame.AckElicitingThreshold)
	require.Equal(t, 1337*time.Microsecond, frame.RequestMaxAckDelay)
	require.Equal(t, protocol.PacketNumber(12345), frame.ReorderingThreshold)
	require.Equal(t, len(data), l)
}

func TestParseAckFrequencyMaxAckDelayOverflow(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)                     // sequence number
	data = append(data, encodeVarInt(0xcafe)...)         // threshold
	data = append(data, encodeVarInt(quicvarint.Max)...) // update max ack delay
	data = append(data, encodeVarInt(12345)...)          // reordering threshold
	frame, l, err := parseAckFrequencyFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Greater(t, frame.RequestMaxAckDelay, time.Duration(0))
	require.Equal(t, frame.RequestMaxAckDelay, time.Duration(math.MaxInt64))
	require.Equal(t, len(data), l)
}

func TestParseAckFrequencyErrorsOnEOFs(t *testing.T) {
	data := append([]byte{}, encodeVarInt(0xdeadbeef)...) // sequence number
	data = append(data, encodeVarInt(0xcafe)...)          // threshold
	data = append(data, encodeVarInt(1337)...)            // update max ack delay
	data = append(data, encodeVarInt(12345)...)           // reordering threshold
	_, l, err := parseAckFrequencyFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parseAckFrequencyFrame(data[:i], protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestWriteAckFrequencyFrame(t *testing.T) {
	frame := &AckFrequencyFrame{
		SequenceNumber:        0xdecafbad,
		AckElicitingThreshold: 0xdeadbeef,
		RequestMaxAckDelay:    12345 * time.Microsecond,
		ReorderingThreshold:   1337,
	}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := encodeVarInt(uint64(FrameTypeAckFrequency))
	expected = append(expected, encodeVarInt(0xdecafbad)...)
	expected = append(expected, encodeVarInt(0xdeadbeef)...)
	expected = append(expected, encodeVarInt(12345)...)
	expected = append(expected, encodeVarInt(1337)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(frame.Length(protocol.Version1)))
}
