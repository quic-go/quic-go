package ackhandler

import "github.com/lucas-clemente/quic-go/protocol"

// A Packet is a packet
type Packet struct {
	PacketNumber protocol.PacketNumber
	Plaintext    []byte
	EntropyBit   bool
	Entropy      EntropyAccumulator

	MissingReports uint8
}
