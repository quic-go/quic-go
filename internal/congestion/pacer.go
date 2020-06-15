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
	budgetAtLastSent protocol.ByteCount
	lastSentTime     time.Time
	bandwidth        uint64 // in bytes / s
}

func newPacer(bw uint64) *pacer {
	return &pacer{
		bandwidth:        bw,
		budgetAtLastSent: maxBurstSize,
	}
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

func (p *pacer) SetBandwidth(bw uint64) {
	if bw == 0 {
		panic("zero bandwidth")
	}
	p.bandwidth = bw
}

func (p *pacer) Budget(now time.Time) protocol.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.budgetAtLastSent
	}
	return utils.MinByteCount(
		maxBurstSize,
		p.budgetAtLastSent+(protocol.ByteCount(p.bandwidth)*protocol.ByteCount(now.Sub(p.lastSentTime).Nanoseconds()))/1e9,
	)
}

// TimeUntilSend returns when the next packet should be sent.
func (p *pacer) TimeUntilSend() time.Time {
	if p.budgetAtLastSent >= maxDatagramSize {
		return time.Time{}
	}
	// TODO: don't allow pacing faster than MinPacingDelay
	return p.lastSentTime.Add(time.Duration(math.Ceil(float64(maxDatagramSize-p.budgetAtLastSent)*1e9/float64(p.bandwidth))) * time.Nanosecond)
}
