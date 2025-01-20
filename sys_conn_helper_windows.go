//go:build windows

package quic

import (
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	GSO_SIZE          = 1500
	UDP_SEND_MSG_SIZE = windows.UDP_SEND_MSG_SIZE
)

const batchSize = 8 // TO DO: Check if this is correct and works for windows too.

// TO DO: Check what this option (SNDBUF, RCVBUF) does when I try to set something above "max".

func forceSetReceiveBuffer(c syscall.RawConn, bytes int) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, bytes)
	}); err != nil {
		return err
	}
	return serr
}

func forceSetSendBuffer(c syscall.RawConn, bytes int) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, bytes)
	}); err != nil {
		return err
	}
	return serr
}

func appendUDPSegmentSizeMsg([]byte, uint16) []byte { return nil }

func isGSOEnabled(conn syscall.RawConn) bool {
	gsoSegmentSize := getMaxGSOSegments()
	if gsoSegmentSize == 512 {
		return true
	}
	return false
}

// TO DO: Implement
func isECNEnabled() bool {
	return false
}

// I'm unable to find windows' response upon a failure caused related to GSO. TO DO
// Quinn just checks for GSO support using isGSOEnabled, nothing else.
func isGSOError(error) bool {
	return false
}

// This was written for linux, not applicable to windows.
func isPermissionError(err error) bool { return false }

// return the maximum number of GSO segments that can be sent
// if GSO is not supported, return 1
// if GSO is supported, return 512
func getMaxGSOSegments() int {
	// On Windows, GSO is supported if UDP_SEND_MSG_SIZE socket option is available
	// We can check this by trying to set it on a dummy socket
	dummy, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return 1
	}
	defer syscall.CloseHandle(dummy)

	err = syscall.SetsockoptInt(dummy, windows.IPPROTO_UDP, windows.UDP_SEND_MSG_SIZE, GSO_SIZE)
	if err != nil {
		return 1
	}
	return 512
}

// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/shared/ws2def.h#L726
type Cmsghdr struct {
	Len   uint64
	Level int32
	Type  int32
}

const SizeofCmsghdr = 0x10 // 16
// TO DO: Is this okay to do?
const CmsgAlign = 0x8 // 8

func cmsgHdrAlign(len uintptr) uintptr {
	return (len + uintptr(CmsgAlign) - 1) & ^(uintptr(CmsgAlign) - 1)
}

func cmsgDataAlign(len uintptr) uintptr {
	return (len + uintptr(0x8) - 1) & ^(uintptr(0x8) - 1)
}
