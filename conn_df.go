//go:build !linux && !windows
// +build !linux,!windows

package quic

import "syscall"

func setDF(rawConn syscall.RawConn) error {
	// no-op on unsupported platforms
	return nil
}
