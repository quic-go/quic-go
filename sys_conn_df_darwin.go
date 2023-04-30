//go:build ignore

package quic

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func setDF(rawConn syscall.RawConn) error {
	// Enabling IP_MTU_DISCOVER will force the kernel to return "sendto: message too long"
	// and the datagram will not be fragmented
	var errDFIPv4, errDFIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		errDFIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	}); err != nil {
		return err
	}
	fmt.Println("v4", errDFIPv4, "v6", errDFIPv6)
	switch {
	case errDFIPv4 == nil && errDFIPv6 == nil:
		fmt.Println("Setting DF for IPv4 and IPv6.")
	case errDFIPv4 == nil && errDFIPv6 != nil:
		fmt.Println("Setting DF for IPv4.")
	case errDFIPv4 != nil && errDFIPv6 == nil:
		fmt.Println("Setting DF for IPv6.")
	case errDFIPv4 != nil && errDFIPv6 != nil:
		return errors.New("setting DF failed for both IPv4 and IPv6")
	}
	return nil
}

func isMsgSizeErr(err error) bool {
	// https://man7.org/linux/man-pages/man7/udp.7.html
	return errors.Is(err, unix.EMSGSIZE)
}

func appendUDPSegmentSizeMsg(b []byte, _ int) []byte { return b }
