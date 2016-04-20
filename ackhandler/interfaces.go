package ackhandler

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

type OutgoingPacketAckHandler interface {
	SentPacket(packet *Packet) error
	ReceivedAck(ackFrame *frames.AckFrame)

	DequeuePacketForRetransmission() (packet *Packet)
}

type IncomingPacketAckHandler interface {
	ReceivedPacket(packetNumber protocol.PacketNumber, entropyBit bool)

	DequeueAckFrame() *frames.AckFrame
}
