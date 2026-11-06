//go:build linux

package quic

import (
	"os"

	"golang.org/x/sys/unix"
)

var (
	errGSO          = &os.SyscallError{Err: unix.EIO}
	errNotPermitted = &os.SyscallError{Syscall: "sendmsg", Err: unix.EPERM}
)
