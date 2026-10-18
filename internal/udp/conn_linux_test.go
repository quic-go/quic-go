//go:build linux

package udp

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/require"
)

var (
	errGSO          = &os.SyscallError{Err: unix.EIO}
	errNotPermitted = &os.SyscallError{Syscall: "sendmsg", Err: unix.EPERM}
)

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

func TestGSOError(t *testing.T) {
	require.True(t, IsGSOError(errGSO))
	require.False(t, IsGSOError(nil))
	require.False(t, IsGSOError(errors.New("test")))
}

func init() {
	major, minor := kernelVersion()
	fmt.Printf("Kernel Version: %d.%d\n\n", major, minor)
}
