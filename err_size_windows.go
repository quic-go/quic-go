//go:build windows
// +build windows

package quic

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isMsgSizeErr(err error) bool {
	// https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
	return errors.Is(err, windows.WSAEMSGSIZE)
}
