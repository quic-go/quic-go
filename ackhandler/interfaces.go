package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	SentPacket(packet *Packet) error
	ReceivedAck(ackFrame *frames.AckFrame) (time.Duration, error)

	DequeuePacketForRetransmission() (packet *Packet)

	BytesInFlight() uint64
}

// ReceivedPacketHandler handles ACKs needed to send for incoming packets
type ReceivedPacketHandler interface {
	ReceivedPacket(packetNumber protocol.PacketNumber, entropyBit bool) error
	ReceivedStopWaiting(*frames.StopWaitingFrame) error

	DequeueAckFrame() *frames.AckFrame
}

// StopWaitingManager manages StopWaitings for sent packets
type StopWaitingManager interface {
	RegisterPacketForRetransmission(packet *Packet)
	GetStopWaitingFrame() *frames.StopWaitingFrame
	SentStopWaitingWithPacket(packetNumber protocol.PacketNumber)
	ReceivedAckForPacketNumber(packetNumber protocol.PacketNumber)
}
