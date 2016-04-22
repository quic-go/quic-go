package ackhandler

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// OutgoingPacketAckHandler handles ACKs received for outgoing packets
type OutgoingPacketAckHandler interface {
	SentPacket(packet *Packet) error
	ReceivedAck(ackFrame *frames.AckFrame) error

	DequeuePacketForRetransmission() (packet *Packet)
}

// IncomingPacketAckHandler handles ACKs needed to send for incoming packets
type IncomingPacketAckHandler interface {
	ReceivedPacket(packetNumber protocol.PacketNumber, entropyBit bool) error

	DequeueAckFrame() *frames.AckFrame
}
