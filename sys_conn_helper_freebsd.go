//go:build freebsd

package quic

import "golang.org/x/sys/unix"

const (
	msgTypeIPTOS       = unix.IP_RECVTOS
	ipv4RECVPKTINFO    = 0x7
	msgTypeIPv4PKTINFO = 0x7
)

const batchSize = 8
