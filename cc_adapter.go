package quic

import (
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// ccAdapter wraps a public CongestionController to satisfy the internal
// congestion.SendAlgorithmWithDebugInfos interface.
// This allows users to inject custom congestion controllers without exposing internal types.
type ccAdapter struct {
	cc CongestionController
}

var _ congestion.SendAlgorithmWithDebugInfos = &ccAdapter{}

// TimeUntilSend disables pacing for custom congestion controllers.
func (a *ccAdapter) TimeUntilSend(_ protocol.ByteCount) monotime.Time { return 0 }

// HasPacingBudget always returns true, disabling pacing for custom congestion controllers.
func (a *ccAdapter) HasPacingBudget(_ monotime.Time) bool { return true }

// MaybeExitSlowStart is a no-op for custom congestion controllers.
func (a *ccAdapter) MaybeExitSlowStart() {}

// InSlowStart returns false; custom controllers manage their own slow start state.
func (a *ccAdapter) InSlowStart() bool { return false }

// InRecovery returns false; custom controllers manage their own recovery state.
func (a *ccAdapter) InRecovery() bool { return false }

// GetCongestionWindow returns 0; custom controllers express the window via CanSend.
func (a *ccAdapter) GetCongestionWindow() protocol.ByteCount { return 0 }

func (a *ccAdapter) OnPacketSent(
	sentTime monotime.Time,
	bytesInFlight protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	a.cc.OnPacketSent(sentTime.ToTime(), bytesInFlight, packetNumber, bytes, isRetransmittable)
}

func (a *ccAdapter) CanSend(bytesInFlight protocol.ByteCount) bool {
	return a.cc.CanSend(bytesInFlight)
}

func (a *ccAdapter) OnPacketAcked(
	number protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	a.cc.OnPacketAcked(number, ackedBytes, priorInFlight, eventTime.ToTime())
}

func (a *ccAdapter) OnCongestionEvent(
	number protocol.PacketNumber,
	lostBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
) {
	a.cc.OnCongestionEvent(number, lostBytes, priorInFlight)
}

func (a *ccAdapter) OnRetransmissionTimeout(packetsRetransmitted bool) {
	a.cc.OnRetransmissionTimeout(packetsRetransmitted)
}

func (a *ccAdapter) SetMaxDatagramSize(s protocol.ByteCount) {
	a.cc.SetMaxDatagramSize(s)
}
