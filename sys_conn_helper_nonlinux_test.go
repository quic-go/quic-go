//go:build !linux

package quic

import "errors"

var (
	errGSO          = errors.New("fake GSO error")
	errNotPermitted = errors.New("fake not permitted error")
)
