//go:build !openbsd

package quic

import "math"

// No platform limit on the requestable socket buffer size; see sys_conn_buffers_openbsd.go.
const maxSocketBufferSize = math.MaxInt
