package congestion

import "github.com/lucas-clemente/quic-go/protocol"

type PacketInfo struct {
	Number protocol.PacketNumber
	Length uint64
}

type PacketVector []PacketInfo
