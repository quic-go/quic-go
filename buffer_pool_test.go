package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestBufferPoolSizes(t *testing.T) {
	buf1 := getPacketBuffer()
	require.Equal(t, protocol.MaxPacketBufferSize, cap(buf1.Data))
	require.Zero(t, buf1.Len())
	buf1.Data = append(buf1.Data, []byte("foobar")...)
	require.Equal(t, protocol.ByteCount(6), buf1.Len())

	buf2 := getLargePacketBuffer()
	require.Equal(t, protocol.MaxLargePacketBufferSize, cap(buf2.Data))
	require.Zero(t, buf2.Len())
}

func TestBufferPoolRelease(t *testing.T) {
	buf1 := getPacketBuffer()
	buf1.Release()
	// panics if released twice
	require.Panics(t, func() { buf1.Release() })

	// panics if wrong-sized buffers are passed
	buf2 := getLargePacketBuffer()
	buf2.Data = make([]byte, 10) // replace the underlying slice
	require.Panics(t, func() { buf2.Release() })
}

func TestBufferPoolSplitting(t *testing.T) {
	buf := getPacketBuffer()
	buf.Split()
	buf.Split()
	// now we have 3 parts
	buf.Decrement()
	buf.Decrement()
	buf.Decrement()
	require.Panics(t, func() { buf.Decrement() })
}
