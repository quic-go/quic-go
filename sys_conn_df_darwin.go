//go:build darwin

package quic

import (
	"errors"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go/internal/utils"
)

func setDF(rawConn syscall.RawConn) (bool, error) {
	uname := &unix.Utsname{}
	err := unix.Uname(uname)
	if err != nil {
		return false, err
	}
	if !isAtLeastOS11(uname) {
		return false, nil
	}

	// Enabling IP_DONTFRAG will force the kernel to return "sendto: message too long"
	// and the datagram will not be fragmented
	var errDFIPv4, errDFIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		errDFIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	}); err != nil {
		return false, err
	}
	switch {
	case errDFIPv4 == nil && errDFIPv6 == nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv4 and IPv6.")
	case errDFIPv4 == nil && errDFIPv6 != nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv4.")
	case errDFIPv4 != nil && errDFIPv6 == nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv6.")
		// On macOS DF bit for IPv4 cannot be set on dual-stack listeners.
		// Better to be safe here.
		return false, nil
	case errDFIPv4 != nil && errDFIPv6 != nil:
		return false, errors.New("setting DF failed for both IPv4 and IPv6")
	}
	return true, nil
}

func isMsgSizeErr(err error) bool {
	return errors.Is(err, unix.EMSGSIZE)
}

func isAtLeastOS11(uname *unix.Utsname) bool {
	release := string(uname.Release[:])
	if idx := strings.Index(release, "."); idx != -1 {
		version, err := strconv.Atoi(release[:idx])
		if err != nil {
			return false
		}
		// Darwin version 20 is macOS version 11
		// https://en.wikipedia.org/wiki/Darwin_(operating_system)#Darwin_20_onwards
		return version >= 20
	}
	return false
}
