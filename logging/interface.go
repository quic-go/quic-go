// Package logging defines a logging interface for quic-go.
// This package should not be considered stable
package logging

import (
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type Tracer interface {
	TracerForServer(odcid protocol.ConnectionID) ConnectionTracer
	TracerForClient(odcid protocol.ConnectionID) ConnectionTracer
}

// A ConnectionTracer records events.
type ConnectionTracer interface {
	StartedConnection(local, remote net.Addr, version protocol.VersionNumber, srcConnID, destConnID protocol.ConnectionID)
	ClosedConnection(CloseReason)
	SentTransportParameters(*wire.TransportParameters)
	ReceivedTransportParameters(*wire.TransportParameters)
	SentPacket(hdr *wire.ExtendedHeader, packetSize protocol.ByteCount, ack *wire.AckFrame, frames []wire.Frame)
	ReceivedVersionNegotiationPacket(*wire.Header)
	ReceivedRetry(*wire.Header)
	ReceivedPacket(hdr *wire.ExtendedHeader, packetSize protocol.ByteCount, frames []wire.Frame)
	ReceivedStatelessReset(token *[16]byte)
	BufferedPacket(PacketType)
	DroppedPacket(PacketType, protocol.ByteCount, PacketDropReason)
	UpdatedMetrics(rttStats *congestion.RTTStats, cwnd protocol.ByteCount, bytesInFLight protocol.ByteCount, packetsInFlight int)
	LostPacket(protocol.EncryptionLevel, protocol.PacketNumber, PacketLossReason)
	UpdatedPTOCount(value uint32)
	UpdatedKeyFromTLS(protocol.EncryptionLevel, protocol.Perspective)
	UpdatedKey(generation protocol.KeyPhase, remote bool)
	DroppedEncryptionLevel(protocol.EncryptionLevel)
	SetLossTimer(TimerType, protocol.EncryptionLevel, time.Time)
	LossTimerExpired(TimerType, protocol.EncryptionLevel)
	LossTimerCanceled()
	// Close is called when the connection is closed.
	Close()
}
