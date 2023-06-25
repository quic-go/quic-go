//go:build darwin

package quic

import "golang.org/x/sys/unix"

const (
	msgTypeIPTOS       = unix.IP_RECVTOS
	ipv4RECVPKTINFO    = unix.IP_RECVPKTINFO
	msgTypeIPv4PKTINFO = unix.IP_PKTINFO
)

// ReadBatch only returns a single packet on OSX,
// see https://godoc.org/golang.org/x/net/ipv4#PacketConn.ReadBatch.
const batchSize = 1
