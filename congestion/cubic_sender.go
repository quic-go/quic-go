package congestion

import (
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
)

type cubicSender struct {
	hybridSlowStart HybridSlowStart
	prr             PrrSender

	// Track the largest packet that has been sent.
	largestSentPacketNumber protocol.PacketNumber

	// Track the largest packet that has been acked.
	largestAckedPacketNumber protocol.PacketNumber

	// Track the largest packet number outstanding when a CWND cutback occurs.
	largestSentAtLastCutback protocol.PacketNumber

	// Congestion window in packets.
	congestionWindow protocol.PacketNumber

	// Slow start congestion window in packets, aka ssthresh.
	slowstartThreshold protocol.PacketNumber
}

// NewCubicSender makes a new cubic sender
func NewCubicSender(initialCongestionWindow protocol.PacketNumber) SendAlgorithm {
	return &cubicSender{
		congestionWindow: initialCongestionWindow,
	}
}

func (c *cubicSender) TimeUntilSend(now time.Time, bytesInFlight uint64) time.Duration {
	if c.InRecovery() {
		// PRR is used when in recovery.
		return c.prr.TimeUntilSend(c.GetCongestionWindow(), bytesInFlight, c.GetSlowStartThreshold())
	}
	if c.GetCongestionWindow() > bytesInFlight {
		return 0
	}
	return math.MaxInt64
}

func (c *cubicSender) OnPacketSent(sentTime time.Time, bytesInFlight uint64, packetNumber protocol.PacketNumber, bytes uint64, isRetransmittable bool) bool {
	// Only update bytesInFlight for data packets.
	if !isRetransmittable {
		return false
	}
	if c.InRecovery() {
		// PRR is used when in recovery.
		c.prr.OnPacketSent(bytes)
	}
	c.largestSentPacketNumber = packetNumber
	c.hybridSlowStart.OnPacketSent(packetNumber)
	return true
}

func (c *cubicSender) InRecovery() bool {
	return c.largestAckedPacketNumber <= c.largestSentAtLastCutback && c.largestAckedPacketNumber != 0
}

func (c *cubicSender) GetCongestionWindow() uint64 {
	return uint64(c.congestionWindow) * protocol.DefaultTCPMSS
}

func (c *cubicSender) GetSlowStartThreshold() uint64 {
	return uint64(c.slowstartThreshold) * protocol.DefaultTCPMSS
}
