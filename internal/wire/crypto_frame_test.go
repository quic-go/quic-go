package wire

import (
	"io"
	"testing"

	"github.com/Noooste/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParseCryptoFrame(t *testing.T) {
	data := encodeVarInt(0xdecafbad)        // offset
	data = append(data, encodeVarInt(6)...) // length
	data = append(data, []byte("foobar")...)
	frame, l, err := parseCryptoFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(0xdecafbad), frame.Offset)
	require.Equal(t, []byte("foobar"), frame.Data)
	require.Equal(t, len(data), l)
}

func TestParseCryptoFrameErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdecafbad)        // offset
	data = append(data, encodeVarInt(6)...) // data length
	data = append(data, []byte("foobar")...)
	_, l, err := parseCryptoFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parseCryptoFrame(data[:i], protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestWriteCryptoFrame(t *testing.T) {
	f := &CryptoFrame{
		Offset: 0x123456,
		Data:   []byte("foobar"),
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{cryptoFrameType}
	expected = append(expected, encodeVarInt(0x123456)...) // offset
	expected = append(expected, encodeVarInt(6)...)        // length
	expected = append(expected, []byte("foobar")...)
	require.Equal(t, expected, b)
	require.Equal(t, int(f.Length(protocol.Version1)), len(b))
}

func TestCryptoFrameMaxDataLength(t *testing.T) {
	const maxSize = 3000

	data := make([]byte, maxSize)
	f := &CryptoFrame{
		Offset: 0xdeadbeef,
	}
	var frameOneByteTooSmallCounter int
	for i := 1; i < maxSize; i++ {
		f.Data = nil
		maxDataLen := f.MaxDataLen(protocol.ByteCount(i))
		if maxDataLen == 0 { // 0 means that no valid CRYPTO frame can be written
			// check that writing a minimal size CRYPTO frame (i.e. with 1 byte data) is actually larger than the desired size
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

func TestCryptoFrameSplitting(t *testing.T) {
	f := &CryptoFrame{
		Offset: 0x1337,
		Data:   []byte("foobar"),
	}
	hdrLen := f.Length(protocol.Version1) - 6
	new, needsSplit := f.MaybeSplitOffFrame(hdrLen+3, protocol.Version1)
	require.True(t, needsSplit)
	require.Equal(t, []byte("foo"), new.Data)
	require.Equal(t, protocol.ByteCount(0x1337), new.Offset)
	require.Equal(t, []byte("bar"), f.Data)
	require.Equal(t, protocol.ByteCount(0x1337+3), f.Offset)
}

func TestCryptoFrameNoSplitWhenEnoughSpace(t *testing.T) {
	f := &CryptoFrame{
		Offset: 0x1337,
		Data:   []byte("foobar"),
	}
	splitFrame, needsSplit := f.MaybeSplitOffFrame(f.Length(protocol.Version1), protocol.Version1)
	require.False(t, needsSplit)
	require.Nil(t, splitFrame)
}

func TestCryptoFrameNoSplitWhenSizeTooSmall(t *testing.T) {
	f := &CryptoFrame{
		Offset: 0x1337,
		Data:   []byte("foobar"),
	}
	length := f.Length(protocol.Version1) - 6
	for i := protocol.ByteCount(0); i <= length; i++ {
		splitFrame, needsSplit := f.MaybeSplitOffFrame(i, protocol.Version1)
		require.True(t, needsSplit)
		require.Nil(t, splitFrame)
	}
	splitFrame, needsSplit := f.MaybeSplitOffFrame(length+1, protocol.Version1)
	require.True(t, needsSplit)
	require.NotNil(t, splitFrame)
}
