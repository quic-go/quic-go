package udp

import (
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// in the tests for the stream deadlines we set a deadline
// and wait to make an assertion when Read / Write was unblocked
// on the CIs, the timing is a lot less precise, so scale every duration by this factor
func scaleDuration(t time.Duration) time.Duration {
	scaleFactor := 1
	if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
		scaleFactor = f
	}
	if scaleFactor == 0 {
		panic("TIMESCALE_FACTOR is 0")
	}
	return time.Duration(scaleFactor) * t
}

func newUDPConnLocalhost(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestConnCapabilities(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		conn, err := newConn(udpConn, true)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		require.True(t, conn.Capabilities().DF)
	})

	t.Run("IPv6", func(t *testing.T) {
		udpConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
		require.NoError(t, err)
		conn, err := newConn(udpConn, false)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		require.False(t, conn.Capabilities().DF)
	})
}
