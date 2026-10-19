//go:build linux

package quic

import (
	"golang.org/x/sys/unix"
	"os"
)

var (
	errGSO          = &os.SyscallError{Err: unix.EIO}
	errNotPermitted = &os.SyscallError{Syscall: "sendmsg", Err: unix.EPERM}
)
