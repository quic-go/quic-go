package ackhandler

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

type OutgoingPacketAckHandler interface {
	SentPacket(packetNumber protocol.PacketNumber, entropyBit bool, plaintext []byte)
	ReceivedAck(ackFrame *frames.AckFrame)

	DequeuePacketForRetransmission() (packetNumber protocol.PacketNumber, entropyBit bool, plaintext []byte)
}

type IncomingPacketAckHandler interface {
	ReceivedPacket(packetNumber protocol.PacketNumber, entropyBit bool)

	DequeueAckFrame() *frames.AckFrame
}
