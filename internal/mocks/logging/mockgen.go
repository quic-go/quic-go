//go:build gomock || generate

package mocklogging

import (
	"net"
	"time"

	"github.com/quic-go/quic-go/logging"
)

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package internal -destination internal/tracer.go github.com/quic-go/quic-go/internal/mocks/logging Tracer"
type Tracer interface {
	SentPacket(net.Addr, *logging.Header, logging.ByteCount, []logging.Frame)
	SentVersionNegotiationPacket(_ net.Addr, dest, src logging.ArbitraryLenConnectionID, _ []logging.VersionNumber)
	DroppedPacket(net.Addr, logging.PacketType, logging.ByteCount, logging.PacketDropReason)
}

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package internal -destination internal/connection_tracer.go github.com/quic-go/quic-go/internal/mocks/logging ConnectionTracer"
type ConnectionTracer interface {
	StartedConnection(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID)
	NegotiatedVersion(chosen logging.VersionNumber, clientVersions, serverVersions []logging.VersionNumber)
	ClosedConnection(error)
	SentTransportParameters(*logging.TransportParameters)
	ReceivedTransportParameters(*logging.TransportParameters)
	RestoredTransportParameters(parameters *logging.TransportParameters) // for 0-RTT
	SentLongHeaderPacket(*logging.ExtendedHeader, logging.ByteCount, logging.ECN, *logging.AckFrame, []logging.Frame)
	SentShortHeaderPacket(*logging.ShortHeader, logging.ByteCount, logging.ECN, *logging.AckFrame, []logging.Frame)
	ReceivedVersionNegotiationPacket(dest, src logging.ArbitraryLenConnectionID, _ []logging.VersionNumber)
	ReceivedRetry(*logging.Header)
	ReceivedLongHeaderPacket(*logging.ExtendedHeader, logging.ByteCount, logging.ECN, []logging.Frame)
	ReceivedShortHeaderPacket(*logging.ShortHeader, logging.ByteCount, logging.ECN, []logging.Frame)
	BufferedPacket(logging.PacketType, logging.ByteCount)
	DroppedPacket(logging.PacketType, logging.ByteCount, logging.PacketDropReason)
	UpdatedMetrics(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int)
	AcknowledgedPacket(logging.EncryptionLevel, logging.PacketNumber)
	LostPacket(logging.EncryptionLevel, logging.PacketNumber, logging.PacketLossReason)
	UpdatedCongestionState(logging.CongestionState)
	UpdatedPTOCount(value uint32)
	UpdatedKeyFromTLS(logging.EncryptionLevel, logging.Perspective)
	UpdatedKey(generation logging.KeyPhase, remote bool)
	DroppedEncryptionLevel(logging.EncryptionLevel)
	DroppedKey(generation logging.KeyPhase)
	SetLossTimer(logging.TimerType, logging.EncryptionLevel, time.Time)
	LossTimerExpired(logging.TimerType, logging.EncryptionLevel)
	LossTimerCanceled()
	ECNStateUpdated(state logging.ECNState, trigger logging.ECNStateTrigger)
	// Close is called when the connection is closed.
	Close()
	Debug(name, msg string)
}
