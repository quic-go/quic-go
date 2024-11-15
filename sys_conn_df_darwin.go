//go:build darwin

package quic

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func setDF(rawConn syscall.RawConn) (bool, error) {
	// Setting DF bit is only supported from macOS11
	// https://github.com/chromium/chromium/blob/117.0.5881.2/net/socket/udp_socket_posix.cc#L555
	if supportsDF, err := isAtLeastMacOS11(); !supportsDF || err != nil {
		return false, err
	}

	var controlErr error
	if err := rawConn.Control(func(fd uintptr) {
		addr, err := unix.Getsockname(int(fd))
		if err != nil {
			controlErr = fmt.Errorf("getsockname: %w", err)
			return
		}
		// Dual-stack sockets are effectively IPv6 sockets (with IPV6_ONLY set to 0).
		// On macOS, the DF bit on dual-stack sockets is controlled by the IPV6_DONTFRAG option.
		// See https://datatracker.ietf.org/doc/draft-seemann-tsvwg-udp-fragmentation/ for details.
		switch addr.(type) {
		case *unix.SockaddrInet4:
			controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		case *unix.SockaddrInet6:
			controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
		default:
			controlErr = fmt.Errorf("unknown address type: %T", addr)
		}
	}); err != nil {
		return false, err
	}
	return controlErr == nil, controlErr
}

func isSendMsgSizeErr(err error) bool {
	return errors.Is(err, unix.EMSGSIZE)
}

func isRecvMsgSizeErr(error) bool { return false }

func isAtLeastMacOS11() (bool, error) {
	uname := &unix.Utsname{}
	err := unix.Uname(uname)
	if err != nil {
		return false, err
	}

	release := string(uname.Release[:])
	if idx := strings.Index(release, "."); idx != -1 {
		version, err := strconv.Atoi(release[:idx])
		if err != nil {
			return false, err
		}
		// Darwin version 20 is macOS version 11
		// https://en.wikipedia.org/wiki/Darwin_(operating_system)#Darwin_20_onwards
		return version >= 20, nil
	}
	return false, nil
}
