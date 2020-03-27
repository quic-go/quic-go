package main

import (
	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"time"
)

const tusConst = protocol.ByteCount(time.Second) * protocol.ByteCount(protocol.MaxPacketSizeIPv4)

type brutalCC struct {
	rttStats             *congestion.RTTStats
	targetBytesPerSecond protocol.ByteCount
}

func NewBrutalSender(targetBytesPerSecond protocol.ByteCount) *brutalCC {
	return &brutalCC{
		targetBytesPerSecond: targetBytesPerSecond,
	}
}

func (b *brutalCC) SetRTTStats(rttStats *congestion.RTTStats) {
	b.rttStats = rttStats
}

func (b *brutalCC) TimeUntilSend(bytesInFlight protocol.ByteCount) time.Duration {
	return time.Duration(tusConst / (2 * b.targetBytesPerSecond))
}

func (b *brutalCC) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	return
}

func (b *brutalCC) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *brutalCC) MaybeExitSlowStart() {
	return
}

func (b *brutalCC) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime time.Time) {
	return
}

func (b *brutalCC) OnPacketLost(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	return
}

func (b *brutalCC) OnRetransmissionTimeout(packetsRetransmitted bool) {
	return
}

func (b *brutalCC) InSlowStart() bool {
	return false
}

func (b *brutalCC) InRecovery() bool {
	return false
}

func (b *brutalCC) GetCongestionWindow() protocol.ByteCount {
	rtt := utils.MaxDuration(b.rttStats.LatestRTT(), b.rttStats.SmoothedRTT())
	if rtt <= 0 {
		return 10240
	}
	return b.targetBytesPerSecond * protocol.ByteCount(rtt) / protocol.ByteCount(time.Second)
}
