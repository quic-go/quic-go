package wire

import (
	"bytes"
	"io"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParseStreamFrameWithOffBit(t *testing.T) {
	data := encodeVarInt(0x12345)                    // stream ID
	data = append(data, encodeVarInt(0xdecafbad)...) // offset
	data = append(data, []byte("foobar")...)
	frame, l, err := parseStreamFrame(data, 0x8^0x4, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamID(0x12345), frame.StreamID)
	require.Equal(t, []byte("foobar"), frame.Data)
	require.False(t, frame.Fin)
	require.Equal(t, protocol.ByteCount(0xdecafbad), frame.Offset)
	require.Equal(t, len(data), l)
}

func TestParseStreamFrameRespectsLEN(t *testing.T) {
	data := encodeVarInt(0x12345)           // stream ID
	data = append(data, encodeVarInt(4)...) // data length
	data = append(data, []byte("foobar")...)
	frame, l, err := parseStreamFrame(data, 0x8^0x2, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamID(0x12345), frame.StreamID)
	require.Equal(t, []byte("foob"), frame.Data)
	require.False(t, frame.Fin)
	require.Zero(t, frame.Offset)
	require.Equal(t, len(data)-2, l)
}

func TestParseStreamFrameWithFINBit(t *testing.T) {
	data := encodeVarInt(9) // stream ID
	data = append(data, []byte("foobar")...)
	frame, l, err := parseStreamFrame(data, 0x8^0x1, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamID(9), frame.StreamID)
	require.Equal(t, []byte("foobar"), frame.Data)
	require.True(t, frame.Fin)
	require.Zero(t, frame.Offset)
	require.Equal(t, len(data), l)
}

func TestParseStreamFrameAllowsEmpty(t *testing.T) {
	data := encodeVarInt(0x1337)                  // stream ID
	data = append(data, encodeVarInt(0x12345)...) // offset
	f, l, err := parseStreamFrame(data, 0x8^0x4, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamID(0x1337), f.StreamID)
	require.Equal(t, protocol.ByteCount(0x12345), f.Offset)
	require.Nil(t, f.Data)
	require.False(t, f.Fin)
	require.Equal(t, len(data), l)
}

func TestParseStreamFrameRejectsOverflow(t *testing.T) {
	data := encodeVarInt(0x12345)                                         // stream ID
	data = append(data, encodeVarInt(uint64(protocol.MaxByteCount-5))...) // offset
	data = append(data, []byte("foobar")...)
	_, _, err := parseStreamFrame(data, 0x8^0x4, protocol.Version1)
	require.EqualError(t, err, "stream data overflows maximum offset")
}

func TestParseStreamFrameRejectsLongFrames(t *testing.T) {
	data := encodeVarInt(0x12345)                                                // stream ID
	data = append(data, encodeVarInt(uint64(protocol.MaxPacketBufferSize)+1)...) // data length
	data = append(data, make([]byte, protocol.MaxPacketBufferSize+1)...)
	_, _, err := parseStreamFrame(data, 0x8^0x2, protocol.Version1)
	require.Equal(t, io.EOF, err)
}

func TestParseStreamFrameRejectsFramesExceedingRemainingSize(t *testing.T) {
	data := encodeVarInt(0x12345)           // stream ID
	data = append(data, encodeVarInt(7)...) // data length
	data = append(data, []byte("foobar")...)
	_, _, err := parseStreamFrame(data, 0x8^0x2, protocol.Version1)
	require.Equal(t, io.EOF, err)
}

func TestParseStreamFrameErrorsOnEOFs(t *testing.T) {
	typ := uint64(0x8 ^ 0x4 ^ 0x2)
	data := encodeVarInt(0x12345)                    // stream ID
	data = append(data, encodeVarInt(0xdecafbad)...) // offset
	data = append(data, encodeVarInt(6)...)          // data length
	data = append(data, []byte("foobar")...)
	_, _, err := parseStreamFrame(data, typ, protocol.Version1)
	require.NoError(t, err)
	for i := range data {
		_, _, err = parseStreamFrame(data[:i], typ, protocol.Version1)
		require.Error(t, err)
	}
}

func TestParseStreamUsesBufferForLongFrames(t *testing.T) {
	data := encodeVarInt(0x12345) // stream ID
	data = append(data, bytes.Repeat([]byte{'f'}, protocol.MinStreamFrameBufferSize)...)
	frame, l, err := parseStreamFrame(data, 0x8, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamID(0x12345), frame.StreamID)
	require.Equal(t, bytes.Repeat([]byte{'f'}, protocol.MinStreamFrameBufferSize), frame.Data)
	require.Equal(t, protocol.ByteCount(protocol.MinStreamFrameBufferSize), frame.DataLen())
	require.False(t, frame.Fin)
	require.True(t, frame.fromPool)
	require.Equal(t, len(data), l)
	require.NotPanics(t, frame.PutBack)
}

func TestParseStreamDoesNotUseBufferForShortFrames(t *testing.T) {
	data := encodeVarInt(0x12345) // stream ID
	data = append(data, bytes.Repeat([]byte{'f'}, protocol.MinStreamFrameBufferSize-1)...)
	frame, l, err := parseStreamFrame(data, 0x8, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamID(0x12345), frame.StreamID)
	require.Equal(t, bytes.Repeat([]byte{'f'}, protocol.MinStreamFrameBufferSize-1), frame.Data)
	require.Equal(t, protocol.ByteCount(protocol.MinStreamFrameBufferSize-1), frame.DataLen())
	require.False(t, frame.Fin)
	require.False(t, frame.fromPool)
	require.Equal(t, len(data), l)
	require.NotPanics(t, frame.PutBack)
}

func TestWriteStreamFrameWithoutOffset(t *testing.T) {
	f := &StreamFrame{
		StreamID: 0x1337,
		Data:     []byte("foobar"),
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x8}
	expected = append(expected, encodeVarInt(0x1337)...) // stream ID
	expected = append(expected, []byte("foobar")...)
	require.Equal(t, expected, b)
	require.Equal(t, int(f.Length(protocol.Version1)), len(b))
}

func TestWriteStreamFrameWithOffset(t *testing.T) {
	f := &StreamFrame{
		StreamID: 0x1337,
		Offset:   0x123456,
		Data:     []byte("foobar"),
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x8 ^ 0x4}
	expected = append(expected, encodeVarInt(0x1337)...)   // stream ID
	expected = append(expected, encodeVarInt(0x123456)...) // offset
	expected = append(expected, []byte("foobar")...)
	require.Equal(t, expected, b)
	require.Equal(t, int(f.Length(protocol.Version1)), len(b))
}

func TestWriteStreamFrameWithFIN(t *testing.T) {
	f := &StreamFrame{
		StreamID: 0x1337,
		Offset:   0x123456,
		Fin:      true,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x8 ^ 0x4 ^ 0x1}
	expected = append(expected, encodeVarInt(0x1337)...)   // stream ID
	expected = append(expected, encodeVarInt(0x123456)...) // offset
	require.Equal(t, expected, b)
	require.Equal(t, int(f.Length(protocol.Version1)), len(b))
}

func TestWriteStreamFrameWithDataLength(t *testing.T) {
	f := &StreamFrame{
		StreamID:       0x1337,
		Data:           []byte("foobar"),
		DataLenPresent: true,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x8 ^ 0x2}
	expected = append(expected, encodeVarInt(0x1337)...) // stream ID
	expected = append(expected, encodeVarInt(6)...)      // data length
	expected = append(expected, []byte("foobar")...)
	require.Equal(t, expected, b)
	require.Equal(t, int(f.Length(protocol.Version1)), len(b))
}

func TestWriteStreamFrameWithDataLengthAndOffset(t *testing.T) {
	f := &StreamFrame{
		StreamID:       0x1337,
		Data:           []byte("foobar"),
		DataLenPresent: true,
		Offset:         0x123456,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x8 ^ 0x4 ^ 0x2}
	expected = append(expected, encodeVarInt(0x1337)...)   // stream ID
	expected = append(expected, encodeVarInt(0x123456)...) // offset
	expected = append(expected, encodeVarInt(6)...)        // data length
	expected = append(expected, []byte("foobar")...)
	require.Equal(t, expected, b)
	require.Equal(t, int(f.Length(protocol.Version1)), len(b))
}

func TestWriteStreamFrameEmptyFrameWithoutFIN(t *testing.T) {
	f := &StreamFrame{
		StreamID: 0x42,
		Offset:   0x1337,
	}
	_, err := f.Append(nil, protocol.Version1)
	require.EqualError(t, err, "StreamFrame: attempting to write empty frame without FIN")
}

func TestStreamMaxDataLength(t *testing.T) {
	const maxSize = 3000
	data := make([]byte, maxSize)
	f := &StreamFrame{
		StreamID: 0x1337,
		Offset:   0xdeadbeef,
	}
	for i := 1; i < 3000; i++ {
		f.Data = nil
		maxDataLen := f.MaxDataLen(protocol.ByteCount(i), protocol.Version1)
		if maxDataLen == 0 { // 0 means that no valid STREAM frame can be written
			// check that writing a minimal size STREAM frame (i.e. with 1 byte data) is actually larger than the desired size
			f.Data = []byte{0}
			b, err := f.Append(nil, protocol.Version1)
			require.NoError(t, err)
			require.Greater(t, len(b), i)
			continue
		}
		f.Data = data[:int(maxDataLen)]
		b, err := f.Append(nil, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, i, len(b))
	}
}

func TestStreamMaxDataLengthWithDataLenPresent(t *testing.T) {
	const maxSize = 3000
	data := make([]byte, maxSize)
	f := &StreamFrame{
		StreamID:       0x1337,
		Offset:         0xdeadbeef,
		DataLenPresent: true,
	}
	var frameOneByteTooSmallCounter int
	for i := 1; i < 3000; i++ {
		f.Data = nil
		maxDataLen := f.MaxDataLen(protocol.ByteCount(i), protocol.Version1)
		if maxDataLen == 0 { // 0 means that no valid STREAM frame can be written
			// check that writing a minimal size STREAM frame (i.e. with 1 byte data) is actually larger than the desired size
			f.Data = []byte{0}
			b, err := f.Append(nil, protocol.Version1)
			require.NoError(t, err)
			require.Greater(t, len(b), i)
			continue
		}
		f.Data = data[:int(maxDataLen)]
		b, err := f.Append(nil, protocol.Version1)
		require.NoError(t, err)
		// There's *one* pathological case, where a data length of x can be encoded into 1 byte
		// but a data lengths of x+1 needs 2 bytes
		// In that case, it's impossible to create a STREAM frame of the desired size
		if len(b) == i-1 {
			frameOneByteTooSmallCounter++
			continue
		}
		require.Equal(t, i, len(b))
	}
	require.Equal(t, 1, frameOneByteTooSmallCounter)
}

func TestStreamSplitting(t *testing.T) {
	f := &StreamFrame{
		StreamID:       0x1337,
		DataLenPresent: true,
		Offset:         0x100,
		Data:           []byte("foobar"),
	}
	frame, needsSplit := f.MaybeSplitOffFrame(f.Length(protocol.Version1)-3, protocol.Version1)
	require.True(t, needsSplit)
	require.NotNil(t, frame)
	require.True(t, f.DataLenPresent)
	require.True(t, frame.DataLenPresent)
	require.Equal(t, protocol.ByteCount(0x100), frame.Offset)
	require.Equal(t, []byte("foo"), frame.Data)
	require.Equal(t, protocol.ByteCount(0x100+3), f.Offset)
	require.Equal(t, []byte("bar"), f.Data)
}

func TestStreamSplittingNoSplitForShortFrame(t *testing.T) {
	f := &StreamFrame{
		StreamID:       0x1337,
		DataLenPresent: true,
		Offset:         0xdeadbeef,
		Data:           make([]byte, 100),
	}
	frame, needsSplit := f.MaybeSplitOffFrame(f.Length(protocol.Version1), protocol.Version1)
	require.False(t, needsSplit)
	require.Nil(t, frame)
	require.Equal(t, protocol.ByteCount(100), f.DataLen())
	frame, needsSplit = f.MaybeSplitOffFrame(f.Length(protocol.Version1)-1, protocol.Version1)
	require.True(t, needsSplit)
	require.Equal(t, protocol.ByteCount(99), frame.DataLen())
	f.PutBack()
}

func TestStreamSplittingPreservesFINBit(t *testing.T) {
	f := &StreamFrame{
		StreamID: 0x1337,
		Fin:      true,
		Offset:   0xdeadbeef,
		Data:     make([]byte, 100),
	}
	frame, needsSplit := f.MaybeSplitOffFrame(50, protocol.Version1)
	require.True(t, needsSplit)
	require.NotNil(t, frame)
	require.Less(t, frame.Offset, f.Offset)
	require.True(t, f.Fin)
	require.False(t, frame.Fin)
}

func TestStreamSplittingProducesCorrectLengthFramesWithoutDataLen(t *testing.T) {
	const size = 1000
	f := &StreamFrame{
		StreamID: 0xdecafbad,
		Offset:   0x1234,
		Data:     []byte{0},
	}
	minFrameSize := f.Length(protocol.Version1)
	for i := protocol.ByteCount(0); i < minFrameSize; i++ {
		frame, needsSplit := f.MaybeSplitOffFrame(i, protocol.Version1)
		require.True(t, needsSplit)
		require.Nil(t, frame)
	}
	for i := minFrameSize; i < size; i++ {
		f.fromPool = false
		f.Data = make([]byte, size)
		frame, needsSplit := f.MaybeSplitOffFrame(i, protocol.Version1)
		require.True(t, needsSplit)
		require.Equal(t, i, frame.Length(protocol.Version1))
	}
}

func TestStreamSplittingProducesCorrectLengthFramesWithDataLen(t *testing.T) {
	const size = 1000
	f := &StreamFrame{
		StreamID:       0xdecafbad,
		Offset:         0x1234,
		DataLenPresent: true,
		Data:           []byte{0},
	}
	minFrameSize := f.Length(protocol.Version1)
	for i := protocol.ByteCount(0); i < minFrameSize; i++ {
		frame, needsSplit := f.MaybeSplitOffFrame(i, protocol.Version1)
		require.True(t, needsSplit)
		require.Nil(t, frame)
	}
	var frameOneByteTooSmallCounter int
	for i := minFrameSize; i < size; i++ {
		f.fromPool = false
		f.Data = make([]byte, size)
		newFrame, needsSplit := f.MaybeSplitOffFrame(i, protocol.Version1)
		require.True(t, needsSplit)
		// There's *one* pathological case, where a data length of x can be encoded into 1 byte
		// but a data lengths of x+1 needs 2 bytes
		// In that case, it's impossible to create a STREAM frame of the desired size
		if newFrame.Length(protocol.Version1) == i-1 {
			frameOneByteTooSmallCounter++
			continue
		}
		require.Equal(t, i, newFrame.Length(protocol.Version1))
	}
	require.Equal(t, 1, frameOneByteTooSmallCounter)
}
