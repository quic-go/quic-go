//go:build linux
// +build linux

package quic

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isMsgSizeErr(err error) bool {
	// https://man7.org/linux/man-pages/man7/udp.7.html
	return errors.Is(err, unix.EMSGSIZE)
}
