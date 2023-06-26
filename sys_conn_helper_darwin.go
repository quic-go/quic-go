//go:build darwin

package quic

import "golang.org/x/sys/unix"

const (
	msgTypeIPTOS = unix.IP_RECVTOS
	ipv4PKTINFO  = unix.IP_RECVPKTINFO
)

// ReadBatch only returns a single packet on OSX,
// see https://godoc.org/golang.org/x/net/ipv4#PacketConn.ReadBatch.
const batchSize = 1
