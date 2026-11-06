//go:build linux

package udp

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

var errGSO = &os.SyscallError{Err: unix.EIO}

func TestForcingReceiveBufferSize(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Must be root to force change the receive buffer size")
	}

	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer c.Close()
	syscallConn, err := c.(*net.UDPConn).SyscallConn()
	require.NoError(t, err)

	const small = 256 << 10 // 256 KB
	require.NoError(t, forceSetReceiveBuffer(syscallConn, small))

	size, err := inspectReadBuffer(syscallConn)
	require.NoError(t, err)
	// the kernel doubles this value (to allow space for bookkeeping overhead)
	require.Equal(t, 2*small, size)

	const large = 32 << 20 // 32 MB
	require.NoError(t, forceSetReceiveBuffer(syscallConn, large))
	size, err = inspectReadBuffer(syscallConn)
	require.NoError(t, err)
	// the kernel doubles this value (to allow space for bookkeeping overhead)
	require.Equal(t, 2*large, size)
}

func TestForcingSendBufferSize(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Must be root to force change the send buffer size")
	}

	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer c.Close()
	syscallConn, err := c.(*net.UDPConn).SyscallConn()
	require.NoError(t, err)

	const small = 256 << 10 // 256 KB
	require.NoError(t, forceSetSendBuffer(syscallConn, small))

	size, err := inspectWriteBuffer(syscallConn)
	require.NoError(t, err)
	// the kernel doubles this value (to allow space for bookkeeping overhead)
	require.Equal(t, 2*small, size)

	const large = 32 << 20 // 32 MB
	require.NoError(t, forceSetSendBuffer(syscallConn, large))
	size, err = inspectWriteBuffer(syscallConn)
	require.NoError(t, err)
	// the kernel doubles this value (to allow space for bookkeeping overhead)
	require.Equal(t, 2*large, size)
}

func TestConnGSO(t *testing.T) {
	server := listenUDP(t, "udp4", net.IPv4(127, 0, 0, 1))
	client := listenUDP(t, "udp4", net.IPv4(127, 0, 0, 1))
	require.True(t, client.Capabilities().GSO)

	// the kernel splits the packet into segments of gsoSize bytes, all with the same ECN marking
	_, err := client.WritePacket([]byte("foobarbaz"), server.LocalAddr(), nil, 3, protocol.ECT1)
	require.NoError(t, err)
	for _, s := range []string{"foo", "bar", "baz"} {
		p, err := server.ReadPacket()
		require.NoError(t, err)
		require.Equal(t, s, string(p.Data))
		require.Equal(t, protocol.ECT1, p.ECN)
	}
}

func TestGSOError(t *testing.T) {
	require.True(t, IsGSOError(errGSO))
	require.False(t, IsGSOError(nil))
	require.False(t, IsGSOError(errors.New("test")))
}

func init() {
	major, minor := kernelVersion()
	fmt.Printf("Kernel Version: %d.%d\n\n", major, minor)
}
