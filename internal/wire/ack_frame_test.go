package wire

import (
	"io"
	"math"
	"testing"
	"time"

	"github.com/Noooste/quic-go/internal/protocol"
	"github.com/Noooste/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestParseACKWithoutRanges(t *testing.T) {
	data := encodeVarInt(100)                // largest acked
	data = append(data, encodeVarInt(0)...)  // delay
	data = append(data, encodeVarInt(0)...)  // num blocks
	data = append(data, encodeVarInt(10)...) // first ack block
	var frame AckFrame
	n, err := parseAckFrame(&frame, data, ackFrameType, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	require.Equal(t, protocol.PacketNumber(100), frame.LargestAcked())
	require.Equal(t, protocol.PacketNumber(90), frame.LowestAcked())
	require.False(t, frame.HasMissingRanges())
}

func TestParseACKSinglePacket(t *testing.T) {
	data := encodeVarInt(55)                // largest acked
	data = append(data, encodeVarInt(0)...) // delay
	data = append(data, encodeVarInt(0)...) // num blocks
	data = append(data, encodeVarInt(0)...) // first ack block
	var frame AckFrame
	n, err := parseAckFrame(&frame, data, ackFrameType, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	require.Equal(t, protocol.PacketNumber(55), frame.LargestAcked())
	require.Equal(t, protocol.PacketNumber(55), frame.LowestAcked())
	require.False(t, frame.HasMissingRanges())
}

func TestParseACKAllPacketsFrom0ToLargest(t *testing.T) {
	data := encodeVarInt(20)                 // largest acked
	data = append(data, encodeVarInt(0)...)  // delay
	data = append(data, encodeVarInt(0)...)  // num blocks
	data = append(data, encodeVarInt(20)...) // first ack block
	var frame AckFrame
	n, err := parseAckFrame(&frame, data, ackFrameType, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	require.Equal(t, protocol.PacketNumber(20), frame.LargestAcked())
	require.Equal(t, protocol.PacketNumber(0), frame.LowestAcked())
	require.False(t, frame.HasMissingRanges())
}

func TestParseACKRejectFirstBlockLargerThanLargestAcked(t *testing.T) {
	data := encodeVarInt(20)                 // largest acked
	data = append(data, encodeVarInt(0)...)  // delay
	data = append(data, encodeVarInt(0)...)  // num blocks
	data = append(data, encodeVarInt(21)...) // first ack block
	var frame AckFrame
	_, err := parseAckFrame(&frame, data, ackFrameType, protocol.AckDelayExponent, protocol.Version1)
	require.EqualError(t, err, "invalid first ACK range")
}

func TestParseACKWithSingleBlock(t *testing.T) {
	data := encodeVarInt(1000)                // largest acked
	data = append(data, encodeVarInt(0)...)   // delay
	data = append(data, encodeVarInt(1)...)   // num blocks
	data = append(data, encodeVarInt(100)...) // first ack block
	data = append(data, encodeVarInt(98)...)  // gap
	data = append(data, encodeVarInt(50)...)  // ack block
	var frame AckFrame
	n, err := parseAckFrame(&frame, data, ackFrameType, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	require.Equal(t, protocol.PacketNumber(1000), frame.LargestAcked())
	require.Equal(t, protocol.PacketNumber(750), frame.LowestAcked())
	require.True(t, frame.HasMissingRanges())
	require.Equal(t, []AckRange{
		{Largest: 1000, Smallest: 900},
		{Largest: 800, Smallest: 750},
	}, frame.AckRanges)
}

func TestParseACKWithMultipleBlocks(t *testing.T) {
	data := encodeVarInt(100)               // largest acked
	data = append(data, encodeVarInt(0)...) // delay
	data = append(data, encodeVarInt(2)...) // num blocks
	data = append(data, encodeVarInt(0)...) // first ack block
	data = append(data, encodeVarInt(0)...) // gap
	data = append(data, encodeVarInt(0)...) // ack block
	data = append(data, encodeVarInt(1)...) // gap
	data = append(data, encodeVarInt(1)...) // ack block
	var frame AckFrame
	n, err := parseAckFrame(&frame, data, ackFrameType, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	require.Equal(t, protocol.PacketNumber(100), frame.LargestAcked())
	require.Equal(t, protocol.PacketNumber(94), frame.LowestAcked())
	require.True(t, frame.HasMissingRanges())
	require.Equal(t, []AckRange{
		{Largest: 100, Smallest: 100},
		{Largest: 98, Smallest: 98},
		{Largest: 95, Smallest: 94},
	}, frame.AckRanges)
}

func TestParseACKUseAckDelayExponent(t *testing.T) {
	const delayTime = 1 << 10 * time.Millisecond
	f := &AckFrame{
		AckRanges: []AckRange{{Smallest: 1, Largest: 1}},
		DelayTime: delayTime,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	for i := uint8(0); i < 8; i++ {
		typ, l, err := quicvarint.Parse(b)
		require.NoError(t, err)
		var frame AckFrame
		n, err := parseAckFrame(&frame, b[l:], typ, protocol.AckDelayExponent+i, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, len(b[l:]), n)
		require.Equal(t, delayTime*(1<<i), frame.DelayTime)
	}
}

func TestParseACKHandleDelayTimeOverflow(t *testing.T) {
	data := encodeVarInt(100)                              // largest acked
	data = append(data, encodeVarInt(math.MaxUint64/5)...) // delay
	data = append(data, encodeVarInt(0)...)                // num blocks
	data = append(data, encodeVarInt(0)...)                // first ack block
	var frame AckFrame
	_, err := parseAckFrame(&frame, data, ackFrameType, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Greater(t, frame.DelayTime, time.Duration(0))
	// The maximum encodable duration is ~292 years.
	require.InDelta(t, 292*365*24, frame.DelayTime.Hours(), 365*24)
}

func TestParseACKErrorOnEOF(t *testing.T) {
	data := encodeVarInt(1000)                // largest acked
	data = append(data, encodeVarInt(0)...)   // delay
	data = append(data, encodeVarInt(1)...)   // num blocks
	data = append(data, encodeVarInt(100)...) // first ack block
	data = append(data, encodeVarInt(98)...)  // gap
	data = append(data, encodeVarInt(50)...)  // ack block
	var frame AckFrame
	_, err := parseAckFrame(&frame, data, ackFrameType, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	for i := range data {
		var frame AckFrame
		_, err := parseAckFrame(&frame, data[:i], ackFrameType, protocol.AckDelayExponent, protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestParseACKECN(t *testing.T) {
	data := encodeVarInt(100)                        // largest acked
	data = append(data, encodeVarInt(0)...)          // delay
	data = append(data, encodeVarInt(0)...)          // num blocks
	data = append(data, encodeVarInt(10)...)         // first ack block
	data = append(data, encodeVarInt(0x42)...)       // ECT(0)
	data = append(data, encodeVarInt(0x12345)...)    // ECT(1)
	data = append(data, encodeVarInt(0x12345678)...) // ECN-CE
	var frame AckFrame
	n, err := parseAckFrame(&frame, data, ackECNFrameType, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	require.Equal(t, protocol.PacketNumber(100), frame.LargestAcked())
	require.Equal(t, protocol.PacketNumber(90), frame.LowestAcked())
	require.False(t, frame.HasMissingRanges())
	require.Equal(t, uint64(0x42), frame.ECT0)
	require.Equal(t, uint64(0x12345), frame.ECT1)
	require.Equal(t, uint64(0x12345678), frame.ECNCE)
}

func TestParseACKECNErrorOnEOF(t *testing.T) {
	data := encodeVarInt(1000)                       // largest acked
	data = append(data, encodeVarInt(0)...)          // delay
	data = append(data, encodeVarInt(1)...)          // num blocks
	data = append(data, encodeVarInt(100)...)        // first ack block
	data = append(data, encodeVarInt(98)...)         // gap
	data = append(data, encodeVarInt(50)...)         // ack block
	data = append(data, encodeVarInt(0x42)...)       // ECT(0)
	data = append(data, encodeVarInt(0x12345)...)    // ECT(1)
	data = append(data, encodeVarInt(0x12345678)...) // ECN-CE
	var frame AckFrame
	n, err := parseAckFrame(&frame, data, ackECNFrameType, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	for i := range data {
		var frame AckFrame
		_, err := parseAckFrame(&frame, data[:i], ackECNFrameType, protocol.AckDelayExponent, protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestWriteACKSimpleFrame(t *testing.T) {
	f := &AckFrame{
		AckRanges: []AckRange{{Smallest: 100, Largest: 1337}},
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{ackFrameType}
	expected = append(expected, encodeVarInt(1337)...) // largest acked
	expected = append(expected, 0)                     // delay
	expected = append(expected, encodeVarInt(0)...)    // num ranges
	expected = append(expected, encodeVarInt(1337-100)...)
	require.Equal(t, expected, b)
}

func TestWriteACKECNFrame(t *testing.T) {
	f := &AckFrame{
		AckRanges: []AckRange{{Smallest: 10, Largest: 2000}},
		ECT0:      13,
		ECT1:      37,
		ECNCE:     12345,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, b, int(f.Length(protocol.Version1)))
	expected := []byte{ackECNFrameType}
	expected = append(expected, encodeVarInt(2000)...) // largest acked
	expected = append(expected, 0)                     // delay
	expected = append(expected, encodeVarInt(0)...)    // num ranges
	expected = append(expected, encodeVarInt(2000-10)...)
	expected = append(expected, encodeVarInt(13)...)
	expected = append(expected, encodeVarInt(37)...)
	expected = append(expected, encodeVarInt(12345)...)
	require.Equal(t, expected, b)
}

func TestWriteACKSinglePacket(t *testing.T) {
	f := &AckFrame{
		AckRanges: []AckRange{{Smallest: 0x2eadbeef, Largest: 0x2eadbeef}},
		DelayTime: 18 * time.Millisecond,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, b, int(f.Length(protocol.Version1)))
	typ, l, err := quicvarint.Parse(b)
	require.NoError(t, err)
	b = b[l:]
	var frame AckFrame
	n, err := parseAckFrame(&frame, b, typ, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(b), n)
	require.Equal(t, f, &frame)
	require.False(t, frame.HasMissingRanges())
	require.Equal(t, f.DelayTime, frame.DelayTime)
}

func TestWriteACKManyPackets(t *testing.T) {
	f := &AckFrame{
		AckRanges: []AckRange{{Smallest: 0x1337, Largest: 0x2eadbeef}},
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, b, int(f.Length(protocol.Version1)))
	typ, l, err := quicvarint.Parse(b)
	require.NoError(t, err)
	b = b[l:]
	var frame AckFrame
	n, err := parseAckFrame(&frame, b, typ, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(b), n)
	require.Equal(t, f, &frame)
	require.False(t, frame.HasMissingRanges())
}

func TestWriteACKSingleGap(t *testing.T) {
	f := &AckFrame{
		AckRanges: []AckRange{
			{Smallest: 400, Largest: 1000},
			{Smallest: 100, Largest: 200},
		},
	}
	require.True(t, f.validateAckRanges())
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, b, int(f.Length(protocol.Version1)))
	typ, l, err := quicvarint.Parse(b)
	require.NoError(t, err)
	b = b[l:]
	var frame AckFrame
	n, err := parseAckFrame(&frame, b, typ, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(b), n)
	require.Equal(t, f, &frame)
	require.True(t, frame.HasMissingRanges())
}

func TestWriteACKMultipleRanges(t *testing.T) {
	f := &AckFrame{
		AckRanges: []AckRange{
			{Smallest: 10, Largest: 10},
			{Smallest: 8, Largest: 8},
			{Smallest: 5, Largest: 6},
			{Smallest: 1, Largest: 3},
		},
	}
	require.True(t, f.validateAckRanges())
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, b, int(f.Length(protocol.Version1)))
	typ, l, err := quicvarint.Parse(b)
	require.NoError(t, err)
	b = b[l:]
	var frame AckFrame
	n, err := parseAckFrame(&frame, b, typ, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(b), n)
	require.Equal(t, f, &frame)
	require.True(t, frame.HasMissingRanges())
}

func TestWriteACKLimitMaxSize(t *testing.T) {
	const numRanges = 1000
	ackRanges := make([]AckRange, numRanges)
	for i := protocol.PacketNumber(1); i <= numRanges; i++ {
		ackRanges[numRanges-i] = AckRange{Smallest: 2 * i, Largest: 2 * i}
	}
	f := &AckFrame{AckRanges: ackRanges}
	require.True(t, f.validateAckRanges())
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, b, int(f.Length(protocol.Version1)))
	// make sure the ACK frame is *a little bit* smaller than the MaxAckFrameSize
	require.Greater(t, protocol.ByteCount(len(b)), protocol.MaxAckFrameSize-5)
	require.LessOrEqual(t, protocol.ByteCount(len(b)), protocol.MaxAckFrameSize)
	typ, l, err := quicvarint.Parse(b)
	require.NoError(t, err)
	b = b[l:]
	var frame AckFrame
	n, err := parseAckFrame(&frame, b, typ, protocol.AckDelayExponent, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(b), n)
	require.True(t, frame.HasMissingRanges())
	require.Less(t, len(frame.AckRanges), numRanges) // make sure we dropped some ranges
}

func TestAckRangeValidator(t *testing.T) {
	tests := []struct {
		name      string
		ackRanges []AckRange
		valid     bool
	}{
		{
			name:      "rejects ACKs without ranges",
			ackRanges: nil,
			valid:     false,
		},
		{
			name:      "accepts an ACK without NACK Ranges",
			ackRanges: []AckRange{{Smallest: 1, Largest: 7}},
			valid:     true,
		},
		{
			name: "rejects ACK ranges with Smallest greater than Largest",
			ackRanges: []AckRange{
				{Smallest: 8, Largest: 10},
				{Smallest: 4, Largest: 3},
			},
			valid: false,
		},
		{
			name: "rejects ACK ranges in the wrong order",
			ackRanges: []AckRange{
				{Smallest: 2, Largest: 2},
				{Smallest: 6, Largest: 7},
			},
			valid: false,
		},
		{
			name: "rejects with overlapping ACK ranges",
			ackRanges: []AckRange{
				{Smallest: 5, Largest: 7},
				{Smallest: 2, Largest: 5},
			},
			valid: false,
		},
		{
			name: "rejects ACK ranges that are part of a larger ACK range",
			ackRanges: []AckRange{
				{Smallest: 4, Largest: 7},
				{Smallest: 5, Largest: 6},
			},
			valid: false,
		},
		{
			name: "rejects with directly adjacent ACK ranges",
			ackRanges: []AckRange{
				{Smallest: 5, Largest: 7},
				{Smallest: 2, Largest: 4},
			},
			valid: false,
		},
		{
			name: "accepts an ACK with one lost packet",
			ackRanges: []AckRange{
				{Smallest: 5, Largest: 10},
				{Smallest: 1, Largest: 3},
			},
			valid: true,
		},
		{
			name: "accepts an ACK with multiple lost packets",
			ackRanges: []AckRange{
				{Smallest: 15, Largest: 20},
				{Smallest: 10, Largest: 12},
				{Smallest: 1, Largest: 3},
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ack := AckFrame{AckRanges: tt.ackRanges}
			result := ack.validateAckRanges()
			require.Equal(t, tt.valid, result)
		})
	}
}

func TestAckFrameAcksPacketWithoutRanges(t *testing.T) {
	f := AckFrame{
		AckRanges: []AckRange{{Smallest: 5, Largest: 10}},
	}
	require.False(t, f.AcksPacket(1))
	require.False(t, f.AcksPacket(4))
	require.True(t, f.AcksPacket(5))
	require.True(t, f.AcksPacket(8))
	require.True(t, f.AcksPacket(10))
	require.False(t, f.AcksPacket(11))
	require.False(t, f.AcksPacket(20))
}

func TestAckFrameAcksPacketWithMultipleRanges(t *testing.T) {
	f := AckFrame{
		AckRanges: []AckRange{
			{Smallest: 15, Largest: 20},
			{Smallest: 5, Largest: 8},
		},
	}
	require.False(t, f.AcksPacket(4))
	require.True(t, f.AcksPacket(5))
	require.True(t, f.AcksPacket(6))
	require.True(t, f.AcksPacket(7))
	require.True(t, f.AcksPacket(8))
	require.False(t, f.AcksPacket(9))
	require.False(t, f.AcksPacket(14))
	require.True(t, f.AcksPacket(15))
	require.True(t, f.AcksPacket(18))
	require.True(t, f.AcksPacket(19))
	require.True(t, f.AcksPacket(20))
	require.False(t, f.AcksPacket(21))
}

func TestAckFrameReset(t *testing.T) {
	f := &AckFrame{
		DelayTime: time.Second,
		AckRanges: []AckRange{{Smallest: 1, Largest: 3}},
		ECT0:      1,
		ECT1:      2,
		ECNCE:     3,
	}
	f.Reset()
	require.Empty(t, f.AckRanges)
	require.Equal(t, 1, cap(f.AckRanges))
	require.Zero(t, f.DelayTime)
	require.Zero(t, f.ECT0)
	require.Zero(t, f.ECT1)
	require.Zero(t, f.ECNCE)
}
