//go:build !linux && !windows
// +build !linux,!windows

package quic

func isMsgSizeErr(err error) bool {
	// to be implemented for more specific platforms
	return false
}
