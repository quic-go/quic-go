// +build linux

package quic

import "golang.org/x/sys/unix"

const msgTypeIPTOS = unix.IP_TOS

const (
	ipv4RECVPKTINFO = 0x8
	ipv6RECVPKTINFO = 0x31
)

const (
	msgTypeIPv4PKTINFO = 0x8
	msgTypeIPv6PKTINFO = 0x32
)
