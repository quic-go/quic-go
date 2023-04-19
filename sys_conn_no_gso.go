//go:build darwin || freebsd

package quic

import "syscall"

func maybeSetGSO(_ syscall.RawConn) bool             { return false }
func appendUDPSegmentSizeMsg(_ []byte, _ int) []byte { return nil }
