//go:build darwin || freebsd
// +build darwin freebsd

package quic

import (
	"errors"
	"golang.org/x/sys/unix"
	"syscall"

	"github.com/lucas-clemente/quic-go/internal/utils"
)

func setDF(rawConn syscall.RawConn) error {
	var errDFIPv4, errDFIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		errDFIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	}); err != nil {
		return err
	}
	switch {
	case errDFIPv4 == nil && errDFIPv6 == nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv4 and IPv6.")
	case errDFIPv4 == nil && errDFIPv6 != nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv4.")
	case errDFIPv4 != nil && errDFIPv6 == nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv6.")
	case errDFIPv4 != nil && errDFIPv6 != nil:
		utils.DefaultLogger.Errorf("setting DF failed for both IPv4 and IPv6: errDFIPv4=%s, errDFIPv6=%s", errDFIPv4.Error(), errDFIPv6.Error())
	}
	return nil
}

func isMsgSizeErr(err error) bool {
	// https://www.freebsd.org/cgi/man.cgi?query=ip&apropos=0&sektion=0&manpath=FreeBSD+14.0-current&arch=default&format=html
	return errors.Is(err, unix.EMSGSIZE)
}
