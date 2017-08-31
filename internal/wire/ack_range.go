package wire

import "github.com/lucas-clemente/quic-go/internal/protocol"

// AckRange is an ACK range
type AckRange struct {
	FirstPacketNumber protocol.PacketNumber
	LastPacketNumber  protocol.PacketNumber
}
