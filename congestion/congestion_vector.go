package congestion

import "github.com/lucas-clemente/quic-go/protocol"

type PacketInfo struct {
	Number protocol.PacketNumber
	Length protocol.ByteCount
}

type PacketVector []PacketInfo
