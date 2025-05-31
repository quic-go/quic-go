package quic

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPFragmentation(t *testing.T) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { sink.Close() })
	sinkPort := sink.LocalAddr().(*net.UDPAddr).Port

	canSendIPv4 := func(conn *net.UDPConn) bool {
		_, err := conn.WriteTo([]byte("hello"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sinkPort})
		return err == nil
	}

	canSendIPv6 := func(conn *net.UDPConn) bool {
		_, err := conn.WriteTo([]byte("hello"), &net.UDPAddr{IP: net.IPv6loopback, Port: sinkPort})
		return err == nil
	}

	t.Run("udp4", func(t *testing.T) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		defer conn.Close()

		require.True(t, canSendIPv4(conn))
		require.False(t, canSendIPv6(conn))

		raw, err := conn.SyscallConn()
		require.NoError(t, err)
		canDF, _ := setDF(raw)
		require.True(t, canDF)
	})

	t.Run("udp6", func(t *testing.T) {
		conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
		require.NoError(t, err)
		defer conn.Close()

		require.False(t, canSendIPv4(conn))
		require.True(t, canSendIPv6(conn))

		raw, err := conn.SyscallConn()
		require.NoError(t, err)
		canDF, _ := setDF(raw)
		require.True(t, canDF)
	})

	t.Run("udp, dual-stack", func(t *testing.T) {
		if version, err := getMacOSVersion(); err != nil || version < macOSVersion15 {
			t.Skipf("skipping on darwin %d", version-9)
		}

		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		require.NoError(t, err)
		defer conn.Close()

		require.True(t, canSendIPv4(conn))
		require.True(t, canSendIPv6(conn))

		raw, err := conn.SyscallConn()
		require.NoError(t, err)
		canDF, _ := setDF(raw)
		require.True(t, canDF)
	})

	t.Run("udp, listening on IPv4", func(t *testing.T) {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		defer conn.Close()

		require.True(t, canSendIPv4(conn))
		require.False(t, canSendIPv6(conn))

		raw, err := conn.SyscallConn()
		require.NoError(t, err)
		canDF, _ := setDF(raw)
		require.True(t, canDF)
	})

	t.Run("udp, listening on IPv6", func(t *testing.T) {
		conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
		require.NoError(t, err)
		defer conn.Close()

		require.False(t, canSendIPv4(conn))
		require.True(t, canSendIPv6(conn))

		raw, err := conn.SyscallConn()
		require.NoError(t, err)
		canDF, _ := setDF(raw)
		require.True(t, canDF)
	})
}
