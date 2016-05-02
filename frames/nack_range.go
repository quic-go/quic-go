package frames

import "github.com/lucas-clemente/quic-go/protocol"

// NackRange is a NACK range
type NackRange struct {
	FirstPacketNumber protocol.PacketNumber
	LastPacketNumber  protocol.PacketNumber
}

// Len gets the lengths of a NackRange
func (n *NackRange) Len() uint64 {
	return uint64(n.LastPacketNumber) - uint64(n.FirstPacketNumber)
}

// ContainsPacketNumber checks if a packetNumber is contained in a NACK range
func (n *NackRange) ContainsPacketNumber(packetNumber protocol.PacketNumber) bool {
	if packetNumber >= n.FirstPacketNumber && packetNumber <= n.LastPacketNumber {
		return true
	}
	return false
}
