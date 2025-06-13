package wire

import (
	"bytes"
	"io"
	"testing"

	"github.com/Noooste/uquic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParseShortHeader(t *testing.T) {
	data := []byte{
		0b01000110,
		0xde, 0xad, 0xbe, 0xef,
		0x13, 0x37, 0x99,
	}
	l, pn, pnLen, kp, err := ParseShortHeader(data, 4)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	require.Equal(t, protocol.KeyPhaseOne, kp)
	require.Equal(t, protocol.PacketNumber(0x133799), pn)
	require.Equal(t, protocol.PacketNumberLen3, pnLen)
}

func TestParseShortHeaderNoQUICBit(t *testing.T) {
	data := []byte{
		0b00000101,
		0xde, 0xad, 0xbe, 0xef,
		0x13, 0x37,
	}
	_, _, _, _, err := ParseShortHeader(data, 4)
	require.EqualError(t, err, "not a QUIC packet")
}

func TestParseShortHeaderReservedBitsSet(t *testing.T) {
	data := []byte{
		0b01010101,
		0xde, 0xad, 0xbe, 0xef,
		0x13, 0x37,
	}
	_, pn, _, _, err := ParseShortHeader(data, 4)
	require.EqualError(t, err, ErrInvalidReservedBits.Error())
	require.Equal(t, protocol.PacketNumber(0x1337), pn)
}

func TestParseShortHeaderErrorsWhenPassedLongHeaderPacket(t *testing.T) {
	_, _, _, _, err := ParseShortHeader([]byte{0x80}, 4)
	require.EqualError(t, err, "not a short header packet")
}

func TestParseShortHeaderErrorsOnEOF(t *testing.T) {
	data := []byte{
		0b01000110,
		0xde, 0xad, 0xbe, 0xef,
		0x13, 0x37, 0x99,
	}
	_, _, _, _, err := ParseShortHeader(data, 4)
	require.NoError(t, err)
	for i := range data {
		_, _, _, _, err := ParseShortHeader(data[:i], 4)
		require.EqualError(t, err, io.EOF.Error())
	}
}

func TestShortHeaderLen(t *testing.T) {
	require.Equal(t, protocol.ByteCount(8), ShortHeaderLen(protocol.ParseConnectionID([]byte{1, 2, 3, 4}), protocol.PacketNumberLen3))
	require.Equal(t, protocol.ByteCount(2), ShortHeaderLen(protocol.ParseConnectionID([]byte{}), protocol.PacketNumberLen1))
}

func TestWriteShortHeaderPacket(t *testing.T) {
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	b, err := AppendShortHeader(nil, connID, 1337, 4, protocol.KeyPhaseOne)
	require.NoError(t, err)
	l, pn, pnLen, kp, err := ParseShortHeader(b, 4)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(1337), pn)
	require.Equal(t, protocol.PacketNumberLen4, pnLen)
	require.Equal(t, protocol.KeyPhaseOne, kp)
	require.Equal(t, len(b), l)
}

func TestLogShortHeaderWithConnectionID(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)

	connID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37})
	LogShortHeader(logger, connID, 1337, protocol.PacketNumberLen4, protocol.KeyPhaseOne)
	require.Contains(t, buf.String(), "Short Header{DestConnectionID: deadbeefcafe1337, PacketNumber: 1337, PacketNumberLen: 4, KeyPhase: 1}")
}

func BenchmarkWriteShortHeader(b *testing.B) {
	b.ReportAllocs()
	buf := make([]byte, 100)
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6})
	for i := 0; i < b.N; i++ {
		var err error
		buf, err = AppendShortHeader(buf, connID, 1337, protocol.PacketNumberLen4, protocol.KeyPhaseOne)
		if err != nil {
			b.Fatalf("failed to write short header: %s", err)
		}
		buf = buf[:0]
	}
}
