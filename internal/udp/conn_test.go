package udp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

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
