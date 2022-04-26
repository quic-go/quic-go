package quic

import (
	"fmt"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type mtuDiscoverer interface {
	ShouldSendProbe(now time.Time) bool
	NextProbeTime() time.Time
	GetPing() (ping ackhandler.Frame, datagramSize protocol.ByteCount)
}

const (
	// At some point, we have to stop searching for a higher MTU.
	// We're happy to send a packet that's 10 bytes smaller than the actual MTU.
	maxMTUDiff = 20
	// send a probe packet every mtuProbeDelay RTTs
	mtuProbeDelay = 5
)

type mtuFinder struct {
	lastProbeTime time.Time
	probeInFlight bool
	mtuIncreased  func(protocol.ByteCount)

	rttStats *utils.RTTStats
	current  protocol.ByteCount
	max      protocol.ByteCount // the maximum value, as advertised by the peer (or our maximum size buffer)
	logger   io.Writer
}

var _ mtuDiscoverer = &mtuFinder{}

func newMTUDiscoverer(rttStats *utils.RTTStats, start, max protocol.ByteCount, mtuIncreased func(protocol.ByteCount), logger io.Writer) mtuDiscoverer {
	f := &mtuFinder{
		current:       start,
		rttStats:      rttStats,
		lastProbeTime: time.Now(), // to make sure the first probe packet is not sent immediately
		mtuIncreased:  mtuIncreased,
		logger:        logger,
		max:           max,
	}
	io.WriteString(f.logger, fmt.Sprintf("initializing MTU discover: %s\n", f.lastProbeTime))
	return f
}

func (f *mtuFinder) done() bool {
	return f.max-f.current <= maxMTUDiff+1
}

func (f *mtuFinder) ShouldSendProbe(now time.Time) bool {
	s := f.shouldSendProbe(now)
	io.WriteString(f.logger, fmt.Sprintf("should send probe (%s): %t\n", now, s))
	return s
}

func (f *mtuFinder) shouldSendProbe(now time.Time) bool {
	if f.probeInFlight || f.done() {
		return false
	}
	return !now.Before(f.nextProbeTime(false))
}

// NextProbeTime returns the time when the next probe packet should be sent.
// It returns the zero value if no probe packet should be sent.
func (f *mtuFinder) NextProbeTime() time.Time {
	return f.nextProbeTime(true)
}

func (f *mtuFinder) nextProbeTime(log bool) time.Time {
	if f.probeInFlight || f.done() {
		io.WriteString(f.logger, "next probe time: none\n")
		return time.Time{}
	}
	rtt := f.rttStats.SmoothedRTT()
	next := f.lastProbeTime.Add(mtuProbeDelay * rtt)
	if log {
		io.WriteString(f.logger, fmt.Sprintf("next probe time: %s (last: %s, rtt: %s)\n", next, f.lastProbeTime, rtt))
	}
	return next
}

func (f *mtuFinder) GetPing() (ackhandler.Frame, protocol.ByteCount) {
	size := (f.max + f.current) / 2
	f.lastProbeTime = time.Now()
	io.WriteString(f.logger, fmt.Sprintf("sending MTU Ping (%s): %d bytes\n", f.lastProbeTime, size))
	f.probeInFlight = true
	return ackhandler.Frame{
		Frame: &wire.PingFrame{},
		OnLost: func(wire.Frame) {
			io.WriteString(f.logger, fmt.Sprintf("MTU Ping lost (%s): %d bytes\n", f.lastProbeTime, size))
			f.probeInFlight = false
			f.max = size
		},
		OnAcked: func(wire.Frame) {
			io.WriteString(f.logger, fmt.Sprintf("MTU Ping acknowledged (%s): %d bytes\n", f.lastProbeTime, size))
			f.probeInFlight = false
			f.current = size
			f.mtuIncreased(size)
		},
	}, size
}
