package wire

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsStreamFrameType(t *testing.T) {
	for i := 0x08; i <= 0x0f; i++ {
		require.Truef(t, FrameType(i).IsStreamFrameType(), "FrameType(0x%x).IsStreamFrameType() = false, want true", i)
	}

	require.False(t, FrameType(0x1).IsStreamFrameType())
}
