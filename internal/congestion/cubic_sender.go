package congestion

import (
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlogwriter"
)

type cubicSender struct {
	*renoSender
	cubic *Cubic
}

var (
	_ SendAlgorithm               = &cubicSender{}
	_ SendAlgorithmWithDebugInfos = &cubicSender{}
)

// NewCubicSender makes a new cubic sender.
func NewCubicSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *cubicSender {
	return newCubicSender(
		clock,
		rttStats,
		connStats,
		initialMaxDatagramSize,
		initialCongestionWindow*initialMaxDatagramSize,
		protocol.MaxCongestionWindowPackets*initialMaxDatagramSize,
		qlogger,
	)
}

func newCubicSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize,
	initialCongestionWindow,
	initialMaxCongestionWindow protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *cubicSender {
	return &cubicSender{
		renoSender: newRenoSender(
			clock,
			rttStats,
			connStats,
			initialMaxDatagramSize,
			initialCongestionWindow,
			initialMaxCongestionWindow,
			qlogger,
		),
		cubic: NewCubic(clock),
	}
}

func (c *cubicSender) OnPacketAcked(
	ackedPacketNumber protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	c.renoSender.onPacketAcked(ackedPacketNumber, ackedBytes, priorInFlight, eventTime, c.maybeIncreaseCubicCwnd)
}

func (c *cubicSender) maybeIncreaseCubicCwnd(
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	c.renoSender.maybeIncreaseCwnd(priorInFlight, c.cubic.OnApplicationLimited, func() {
		c.congestionWindow = min(
			c.maxCongestionWindow(),
			c.cubic.CongestionWindowAfterAck(ackedBytes, c.congestionWindow, c.rttStats.MinRTT(), eventTime),
		)
	})
}

func (c *cubicSender) OnCongestionEvent(packetNumber protocol.PacketNumber, lostBytes, priorInFlight protocol.ByteCount) {
	c.renoSender.onCongestionEvent(packetNumber, lostBytes, priorInFlight, nil, func() protocol.ByteCount {
		return c.cubic.CongestionWindowAfterPacketLoss(c.congestionWindow)
	})
}

func (c *cubicSender) OnSpuriousLoss(protocol.PacketNumber) {}

func (c *cubicSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	c.renoSender.OnRetransmissionTimeout(packetsRetransmitted)
	if packetsRetransmitted {
		c.cubic.Reset()
	}
}

func (c *cubicSender) OnConnectionMigration() {
	c.renoSender.OnConnectionMigration()
	c.cubic.Reset()
}
