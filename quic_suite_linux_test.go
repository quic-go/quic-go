//go:build linux

package quic

import (
	"fmt"
)

func init() {
	major, minor := kernelVersion()
	fmt.Printf("Kernel Version: %d.%d\n\n", major, minor)
}
