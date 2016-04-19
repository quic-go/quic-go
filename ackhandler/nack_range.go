package ackhandler

import "github.com/lucas-clemente/quic-go/protocol"

// NackRange is a NACK range
type NackRange struct {
	FirstPacketNumber protocol.PacketNumber
	Length            uint8
}
