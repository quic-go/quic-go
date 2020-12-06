// +build darwin

package quic

import "golang.org/x/sys/unix"

const msgTypeIPTOS = unix.IP_RECVTOS
