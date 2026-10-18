//go:build !linux

package udp

func forceSetReceiveBuffer(c any, bytes int) error { return nil }
func forceSetSendBuffer(c any, bytes int) error    { return nil }

func appendUDPSegmentSizeMsg([]byte, uint16) []byte { return nil }
func IsGSOError(error) bool                         { return false }
func IsPermissionError(err error) bool              { return false }
