package wire

import (
	"io"
	"testing"

	"github.com/Noooste/uquic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParseNewConnectionIDFrame(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)                              // sequence number
	data = append(data, encodeVarInt(0xcafe)...)                  // retire prior to
	data = append(data, 10)                                       // connection ID length
	data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // connection ID
	data = append(data, []byte("deadbeefdecafbad")...)            // stateless reset token
	frame, l, err := parseNewConnectionIDFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, uint64(0xdeadbeef), frame.SequenceNumber)
	require.Equal(t, uint64(0xcafe), frame.RetirePriorTo)
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), frame.ConnectionID)
	require.Equal(t, "deadbeefdecafbad", string(frame.StatelessResetToken[:]))
	require.Equal(t, len(data), l)
}

func TestParseNewConnectionIDRetirePriorToLargerThanSequenceNumber(t *testing.T) {
	data := encodeVarInt(1000)                 // sequence number
	data = append(data, encodeVarInt(1001)...) // retire prior to
	data = append(data, 3)
	data = append(data, []byte{1, 2, 3}...)
	data = append(data, []byte("deadbeefdecafbad")...) // stateless reset token
	_, _, err := parseNewConnectionIDFrame(data, protocol.Version1)
	require.EqualError(t, err, "Retire Prior To value (1001) larger than Sequence Number (1000)")
}

func TestParseNewConnectionIDZeroLengthConnID(t *testing.T) {
	data := encodeVarInt(42)                 // sequence number
	data = append(data, encodeVarInt(12)...) // retire prior to
	data = append(data, 0)                   // connection ID length
	_, _, err := parseNewConnectionIDFrame(data, protocol.Version1)
	require.EqualError(t, err, "invalid zero-length connection ID")
}

func TestParseNewConnectionIDInvalidConnIDLength(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)                                                                          // sequence number
	data = append(data, encodeVarInt(0xcafe)...)                                                              // retire prior to
	data = append(data, 21)                                                                                   // connection ID length
	data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}...) // connection ID
	data = append(data, []byte("deadbeefdecafbad")...)                                                        // stateless reset token
	_, _, err := parseNewConnectionIDFrame(data, protocol.Version1)
	require.Equal(t, protocol.ErrInvalidConnectionIDLen, err)
}

func TestParseNewConnectionIDErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)                              // sequence number
	data = append(data, encodeVarInt(0xcafe1234)...)              // retire prior to
	data = append(data, 10)                                       // connection ID length
	data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // connection ID
	data = append(data, []byte("deadbeefdecafbad")...)            // stateless reset token
	_, l, err := parseNewConnectionIDFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parseNewConnectionIDFrame(data[:i], protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestWriteNewConnectionIDFrame(t *testing.T) {
	token := protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	frame := &NewConnectionIDFrame{
		SequenceNumber:      0x1337,
		RetirePriorTo:       0x42,
		ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6}),
		StatelessResetToken: token,
	}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{newConnectionIDFrameType}
	expected = append(expected, encodeVarInt(0x1337)...)
	expected = append(expected, encodeVarInt(0x42)...)
	expected = append(expected, 6)
	expected = append(expected, []byte{1, 2, 3, 4, 5, 6}...)
	expected = append(expected, token[:]...)
	require.Equal(t, expected, b)
	require.Equal(t, int(frame.Length(protocol.Version1)), len(b))
}
