//go:build !linux && !windows

package quic

import (
	"syscall"
)

func setDF(rawConn syscall.RawConn) error {
	// no-op on unsupported platforms
	return nil
}

// GSO is only supported on Linux
func maybeSetGSO(syscall.RawConn) bool {
	return false
}

func isMsgSizeErr(err error) bool {
	// to be implemented for more specific platforms
	return false
}

func appendUDPSegmentSizeMsg(b []byte, _ int) []byte { return b }
