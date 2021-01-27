package quic

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

const (
	// At some point, we have to stop searching for a higher MTU.
	// We're happy to send a packet that's 10 bytes smaller than the actual MTU.
	maxMTUDiff = 20
	// send a probe packet every mtuProbeDelay RTTs
	mtuProbeDelay = 5
)

type mtuDiscoverer struct {
	lastProbeTime time.Time
	probeInFlight bool
	mtuIncreased  func(protocol.ByteCount)

	rttStats *utils.RTTStats
	current  protocol.ByteCount
	max      protocol.ByteCount // the maximum value, as advertised by the peer (or our maximum size buffer)
}

func newMTUDiscoverer(rttStats *utils.RTTStats, start, max protocol.ByteCount, mtuIncreased func(protocol.ByteCount)) *mtuDiscoverer {
	return &mtuDiscoverer{
		current:       start,
		rttStats:      rttStats,
		lastProbeTime: time.Now(), // to make sure the first probe packet is not sent immediately
		mtuIncreased:  mtuIncreased,
		max:           max,
	}
}

func (d *mtuDiscoverer) done() bool {
	return d.max-d.current <= maxMTUDiff+1
}

func (d *mtuDiscoverer) ShouldSendProbe(now time.Time) bool {
	if d.probeInFlight || d.done() {
		return false
	}
	return !now.Before(d.NextProbeTime())
}

// NextProbeTime returns the time when the next probe packet should be sent.
// It returns the zero value if no probe packet should be sent.
func (d *mtuDiscoverer) NextProbeTime() time.Time {
	if d.probeInFlight || d.done() {
		return time.Time{}
	}
	return d.lastProbeTime.Add(mtuProbeDelay * d.rttStats.SmoothedRTT())
}

func (d *mtuDiscoverer) GetPing() (ackhandler.Frame, protocol.ByteCount) {
	size := (d.max + d.current) / 2
	d.lastProbeTime = time.Now()
	d.probeInFlight = true
	return ackhandler.Frame{
		Frame: &wire.PingFrame{},
		OnLost: func(wire.Frame) {
			d.probeInFlight = false
			d.max = size
		},
		OnAcked: func(wire.Frame) {
			d.probeInFlight = false
			d.current = size
			d.mtuIncreased(size)
		},
	}, size
}
