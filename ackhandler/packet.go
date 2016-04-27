package ackhandler

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// A Packet is a packet
type Packet struct {
	PacketNumber protocol.PacketNumber
	Frames       []frames.Frame
	EntropyBit   bool
	Entropy      EntropyAccumulator

	MissingReports uint8
	Retransmitted  bool // has this Packet ever been retransmitted
}
