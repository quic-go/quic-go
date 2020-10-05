// +build darwin

package quic

import "syscall"

const (
	//nolint:stylecheck
	ip_recvtos   = 27
	msgTypeIPTOS = ip_recvtos
)

func setRECVTOS(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ip_recvtos, 1)
}
