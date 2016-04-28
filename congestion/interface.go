package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
)

type SendAlgorithm interface {
	TimeUntilSend(now time.Time, bytesInFlight uint64) time.Duration
	OnPacketSent(sentTime time.Time, bytesInFlight uint64, packetNumber protocol.PacketNumber, bytes uint64, isRetransmittable bool) bool
	GetCongestionWindow() uint64
	OnCongestionEvent(rttUpdated bool, bytesInFlight uint64, ackedPackets PacketVector, lostPackets PacketVector)
	BandwidthEstimate() Bandwidth
	SetNumEmulatedConnections(n int)
	OnRetransmissionTimeout(packetsRetransmitted bool)
	OnConnectionMigration()
	RetransmissionDelay() time.Duration

	// Experiments
	SetSlowStartLargeReduction(enabled bool)

	// Stuff only used in testing
	// TODO: Maybe make CubicSender public and typeassert in tests?
	HybridSlowStart() *HybridSlowStart
	SlowstartThreshold() protocol.PacketNumber
	RenoBeta() float32
	InRecovery() bool
}
