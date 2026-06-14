package quic

import (
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
)

// ByteCount is the number of bytes.
type ByteCount = protocol.ByteCount

// PacketNumber is a QUIC packet number.
type PacketNumber = protocol.PacketNumber

// CongestionController is the interface for a pluggable congestion controller.
// It is called by the QUIC connection to regulate the sending rate.
//
// Implementations must be safe for concurrent use.
//
// Note: pacing is handled separately by quic-go and is not part of this interface.
// The congestion controller only controls the congestion window.
type CongestionController interface {
	// OnPacketSent is called when a packet containing retransmittable frames is sent.
	OnPacketSent(
		sentTime time.Time,
		bytesInFlight ByteCount,
		packetNumber PacketNumber,
		bytes ByteCount,
		isRetransmittable bool,
	)

	// CanSend returns true if the congestion controller allows sending a packet right now.
	CanSend(bytesInFlight ByteCount) bool

	// OnPacketAcked is called for each packet that is ACKed.
	OnPacketAcked(
		number PacketNumber,
		ackedBytes ByteCount,
		priorInFlight ByteCount,
		eventTime time.Time,
	)

	// OnCongestionEvent is called when packet loss is detected.
	OnCongestionEvent(
		number PacketNumber,
		lostBytes ByteCount,
		priorInFlight ByteCount,
	)

	// OnRetransmissionTimeout is called when a retransmission timeout occurs.
	OnRetransmissionTimeout(packetsRetransmitted bool)

	// SetMaxDatagramSize is called when the maximum datagram size changes.
	SetMaxDatagramSize(size ByteCount)
}
