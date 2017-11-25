package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	// SentPacket may modify the packet
	SentPacket(packet *Packet) error
	ReceivedAck(ackFrame *wire.AckFrame, withPacketNumber protocol.PacketNumber, encLevel protocol.EncryptionLevel, recvTime time.Time) error
	SetHandshakeComplete()

	ShouldSendRetransmittablePacket() bool
	GetStopWaitingFrame(force bool) *wire.StopWaitingFrame
	// TimeUntilSend returns infinite if the congestion controller is congestion window limited, a negative duration if the packet can be sent immediately
	// and a positive duration if sending is pacing limited.
	TimeUntilSend(now time.Time, packetLength protocol.ByteCount) time.Duration
	DequeuePacketForRetransmission() (packet *Packet)
	GetLeastUnacked() protocol.PacketNumber

	GetAlarmTimeout() time.Time
	OnAlarm()
}

// ReceivedPacketHandler handles ACKs needed to send for incoming packets
type ReceivedPacketHandler interface {
	ReceivedPacket(packetNumber protocol.PacketNumber, shouldInstigateAck bool) error
	SetLowerLimit(protocol.PacketNumber)

	GetAlarmTimeout() time.Time
	GetAckFrame() *wire.AckFrame
}
