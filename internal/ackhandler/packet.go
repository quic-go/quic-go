package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// A Packet is a packet
// +gen linkedlist
type Packet struct {
	PacketNumber    protocol.PacketNumber
	PacketType      protocol.PacketType
	Frames          []wire.Frame
	Length          protocol.ByteCount
	EncryptionLevel protocol.EncryptionLevel
	SendTime        time.Time

	largestAcked protocol.PacketNumber // if the packet contains an ACK, the LargestAcked value of that ACK

	queuedForRetransmission bool
	includedInBytesInFlight bool
	retransmittedAs         []protocol.PacketNumber
	isRetransmission        bool // we need a separate bool here because 0 is a valid packet number
	retransmissionOf        protocol.PacketNumber
}
