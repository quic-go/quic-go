// +build linux

package quic

import "syscall"

const msgTypeIPTOS = syscall.IP_TOS

func setRECVTOS(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_RECVTOS, 1)
}
