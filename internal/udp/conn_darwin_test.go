//go:build darwin

package udp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWrapDualStackDF(t *testing.T) {
	version, err := getMacOSVersion()
	require.NoError(t, err)
	conn := listenUDP(t, "udp", nil)
	// setting DF on dual-stack sockets works since macOS 15
	require.Equal(t, version >= macOSVersion15, conn.Capabilities().DF)
}
