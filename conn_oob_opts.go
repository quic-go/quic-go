//go:build !linux && !windows
// +build !linux,!windows

package quic

func setOOBSockOpts(fd uintptr) {
	// no-op on unsupported platforms
}
