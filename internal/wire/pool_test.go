package wire

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestGetAndPutStreamFrames(t *testing.T) {
	f := GetStreamFrame(protocol.MaxPacketBufferSize)
	require.Equal(t, protocol.MaxPacketBufferSize, cap(f.Data))
	putStreamFrame(f)
}

func TestGetAndPutLargeStreamFrames(t *testing.T) {
	f := GetStreamFrame(protocol.MaxPacketBufferSize + 1)
	require.Equal(t, protocol.MaxLargePacketBufferSize, cap(f.Data))
	putStreamFrame(f)
}

func TestGetStreamFrameExceedingPooledSizes(t *testing.T) {
	f := GetStreamFrame(protocol.MaxLargePacketBufferSize + 1)
	require.GreaterOrEqual(t, cap(f.Data), protocol.MaxLargePacketBufferSize+1)
	require.False(t, f.fromPool)
	putStreamFrame(f) // must not panic, and must not be pooled
}

func TestPanicOnPuttingStreamFrameWithWrongCapacity(t *testing.T) {
	f := GetStreamFrame(protocol.MaxPacketBufferSize)
	f.Data = []byte("foobar")
	require.Panics(t, func() { putStreamFrame(f) })
}

func TestAcceptStreamFramesNotFromBuffer(t *testing.T) {
	f := &StreamFrame{Data: []byte("foobar")}
	putStreamFrame(f)
	// No assertion needed as we're just checking it doesn't panic
}
