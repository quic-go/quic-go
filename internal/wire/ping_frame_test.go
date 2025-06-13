package wire

import (
	"testing"

	"github.com/Noooste/uquic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestWritePingFrame(t *testing.T) {
	frame := PingFrame{}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, []byte{0x1}, b)
	require.Len(t, b, int(frame.Length(protocol.Version1)))
}
