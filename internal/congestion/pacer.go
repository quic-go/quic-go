package congestion

import (
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

const maxBurstSize = 10 * maxDatagramSize

// The pacer implements a token bucket pacing algorithm.
type pacer struct {
	budgetAtLastSent     protocol.ByteCount
	lastSentTime         time.Time
	getAdjustedBandwidth func() uint64 // in bytes/s
}

func newPacer(getBandwidth func() Bandwidth) *pacer {
	p := &pacer{getAdjustedBandwidth: func() uint64 {
		// Bandwidth is in bits/s. We need the value in bytes/s.
		bw := uint64(getBandwidth() / BytesPerSecond)
		// Use a slightly higher value than the actual measured bandwidth.
		// RTT variations then won't result in under-utilization of the congestion window.
		// Ultimately, this will  result in sending packets as acknowledgments are received rather than when timers fire,
		// provided the congestion window is fully utilized and acknowledgments arrive at regular intervals.
		return bw * 5 / 4
	}}
	p.budgetAtLastSent = p.maxBurstSize()
	return p
}

func (p *pacer) SentPacket(sendTime time.Time, size protocol.ByteCount) {
	budget := p.Budget(sendTime)
	if size > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

func (p *pacer) Budget(now time.Time) protocol.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	budget := p.budgetAtLastSent + (protocol.ByteCount(p.getAdjustedBandwidth())*protocol.ByteCount(now.Sub(p.lastSentTime).Nanoseconds()))/1e9
	return utils.MinByteCount(p.maxBurstSize(), budget)
}

func (p *pacer) maxBurstSize() protocol.ByteCount {
	return utils.MaxByteCount(
		protocol.ByteCount(uint64((protocol.MinPacingDelay+protocol.TimerGranularity).Nanoseconds())*p.getAdjustedBandwidth())/1e9,
		maxBurstSize,
	)
}

// TimeUntilSend returns when the next packet should be sent.
func (p *pacer) TimeUntilSend() time.Time {
	if p.budgetAtLastSent >= maxDatagramSize {
		return time.Time{}
	}
	return p.lastSentTime.Add(utils.MaxDuration(
		protocol.MinPacingDelay,
		time.Duration(math.Ceil(float64(maxDatagramSize-p.budgetAtLastSent)*1e9/float64(p.getAdjustedBandwidth())))*time.Nanosecond,
	))
}
