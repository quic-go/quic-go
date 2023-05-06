//go:build !linux

package quic

func forceSetReceiveBuffer(c interface{}, bytes int) error { return nil }
