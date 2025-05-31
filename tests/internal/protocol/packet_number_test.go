package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInvalidPacketNumberIsSmallerThanAllValidPacketNumbers(t *testing.T) {
	require.Less(t, InvalidPacketNumber, PacketNumber(0))
}

func TestPacketNumberLenHasCorrectValue(t *testing.T) {
	require.EqualValues(t, 1, PacketNumberLen1)
	require.EqualValues(t, 2, PacketNumberLen2)
	require.EqualValues(t, 3, PacketNumberLen3)
	require.EqualValues(t, 4, PacketNumberLen4)
}

func TestDecodePacketNumber(t *testing.T) {
	require.Equal(t, PacketNumber(255), DecodePacketNumber(PacketNumberLen1, 10, 255))
	require.Equal(t, PacketNumber(0), DecodePacketNumber(PacketNumberLen1, 10, 0))
	require.Equal(t, PacketNumber(256), DecodePacketNumber(PacketNumberLen1, 127, 0))
	require.Equal(t, PacketNumber(256), DecodePacketNumber(PacketNumberLen1, 128, 0))
	require.Equal(t, PacketNumber(256), DecodePacketNumber(PacketNumberLen1, 256+126, 0))
	require.Equal(t, PacketNumber(512), DecodePacketNumber(PacketNumberLen1, 256+127, 0))
	require.Equal(t, PacketNumber(0xffff), DecodePacketNumber(PacketNumberLen2, 0xffff, 0xffff))
	require.Equal(t, PacketNumber(0xffff), DecodePacketNumber(PacketNumberLen2, 0xffff+1, 0xffff))

	// example from https://www.rfc-editor.org/rfc/rfc9000.html#section-a.3
	require.Equal(t, PacketNumber(0xa82f9b32), DecodePacketNumber(PacketNumberLen2, 0xa82f30ea, 0x9b32))
}

func TestPacketNumberLengthForHeader(t *testing.T) {
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForHeader(1, InvalidPacketNumber))
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForHeader(1<<15-2, InvalidPacketNumber))
	require.Equal(t, PacketNumberLen3, PacketNumberLengthForHeader(1<<15-1, InvalidPacketNumber))
	require.Equal(t, PacketNumberLen3, PacketNumberLengthForHeader(1<<23-2, InvalidPacketNumber))
	require.Equal(t, PacketNumberLen4, PacketNumberLengthForHeader(1<<23-1, InvalidPacketNumber))
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForHeader(1<<15+9, 10))
	require.Equal(t, PacketNumberLen3, PacketNumberLengthForHeader(1<<15+10, 10))
	require.Equal(t, PacketNumberLen3, PacketNumberLengthForHeader(1<<23+99, 100))
	require.Equal(t, PacketNumberLen4, PacketNumberLengthForHeader(1<<23+100, 100))
	// examples from https://www.rfc-editor.org/rfc/rfc9000.html#section-a.2
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForHeader(0xac5c02, 0xabe8b3))
	require.Equal(t, PacketNumberLen3, PacketNumberLengthForHeader(0xace8fe, 0xabe8b3))
}
