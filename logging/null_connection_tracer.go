package logging

import (
	"net"
	"time"
)

// The NullConnectionTracer is a ConnectionTracer that does nothing.
// It is useful for embedding. Don't modify this variable!
var NullConnectionTracer ConnectionTracer = &nullConnectionTracer{}

type nullConnectionTracer struct{}

var _ ConnectionTracer = &nullConnectionTracer{}

func (n nullConnectionTracer) StartedConnection(local, remote net.Addr, srcConnID, destConnID ConnectionID) {
}

func (n nullConnectionTracer) NegotiatedVersion(chosen VersionNumber, clientVersions, serverVersions []VersionNumber) {
}
func (n nullConnectionTracer) ClosedConnection(err error)                                         {}
func (n nullConnectionTracer) SentTransportParameters(*TransportParameters)                       {}
func (n nullConnectionTracer) ReceivedTransportParameters(*TransportParameters)                   {}
func (n nullConnectionTracer) RestoredTransportParameters(*TransportParameters)                   {}
func (n nullConnectionTracer) SentPacket(*ExtendedHeader, ByteCount, *AckFrame, []Frame)          {}
func (n nullConnectionTracer) ReceivedVersionNegotiationPacket(*Header, []VersionNumber)          {}
func (n nullConnectionTracer) ReceivedRetry(*Header)                                              {}
func (n nullConnectionTracer) ReceivedPacket(hdr *ExtendedHeader, size ByteCount, frames []Frame) {}
func (n nullConnectionTracer) BufferedPacket(PacketType)                                          {}
func (n nullConnectionTracer) DroppedPacket(PacketType, ByteCount, PacketDropReason)              {}
func (n nullConnectionTracer) UpdatedMetrics(rttStats *RTTStats, cwnd, bytesInFlight ByteCount, packetsInFlight int) {
}
func (n nullConnectionTracer) AcknowledgedPacket(EncryptionLevel, PacketNumber)            {}
func (n nullConnectionTracer) LostPacket(EncryptionLevel, PacketNumber, PacketLossReason)  {}
func (n nullConnectionTracer) UpdatedCongestionState(CongestionState)                      {}
func (n nullConnectionTracer) UpdatedPTOCount(uint32)                                      {}
func (n nullConnectionTracer) UpdatedKeyFromTLS(EncryptionLevel, Perspective)              {}
func (n nullConnectionTracer) UpdatedKey(keyPhase KeyPhase, remote bool)                   {}
func (n nullConnectionTracer) DroppedEncryptionLevel(EncryptionLevel)                      {}
func (n nullConnectionTracer) DroppedKey(KeyPhase)                                         {}
func (n nullConnectionTracer) SetLossTimer(TimerType, EncryptionLevel, time.Time)          {}
func (n nullConnectionTracer) LossTimerExpired(timerType TimerType, level EncryptionLevel) {}
func (n nullConnectionTracer) LossTimerCanceled()                                          {}
func (n nullConnectionTracer) Close()                                                      {}
func (n nullConnectionTracer) Debug(name, msg string)                                      {}
