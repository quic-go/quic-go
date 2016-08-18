package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/ackhandlerlegacy"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	SentPacket(packet *ackhandlerlegacy.Packet) error
	ReceivedAck(ackFrame *frames.AckFrame, withPacketNumber protocol.PacketNumber) error

	GetStopWaitingFrame(force bool) *frames.StopWaitingFrame

	MaybeQueueRTOs()
	DequeuePacketForRetransmission() (packet *ackhandlerlegacy.Packet)

	BytesInFlight() protocol.ByteCount
	GetLeastUnacked() protocol.PacketNumber

	CongestionAllowsSending() bool
	CheckForError() error

	TimeOfFirstRTO() time.Time
}

// ReceivedPacketHandler handles ACKs needed to send for incoming packets
type ReceivedPacketHandler interface {
	// TODO: remove entroypyBit once we drop support for QUIC 33
	ReceivedPacket(packetNumber protocol.PacketNumber, entropyBit bool) error
	ReceivedStopWaiting(*frames.StopWaitingFrame) error

	GetAckFrame(dequeue bool) (*frames.AckFrame, error)
}

// StopWaitingManager manages StopWaitings for sent packets
// TODO: remove once we drop support for QUIC 33
type StopWaitingManager interface {
	RegisterPacketForRetransmission(packet *ackhandlerlegacy.Packet)
	GetStopWaitingFrame() *frames.StopWaitingFrame
	SentStopWaitingWithPacket(packetNumber protocol.PacketNumber)
	ReceivedAckForPacketNumber(packetNumber protocol.PacketNumber)
}
