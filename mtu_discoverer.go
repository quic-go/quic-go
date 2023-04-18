package quic

import (
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type mtuDiscoverer interface {
	// Start starts the MTU discovery process.
	// It's unnecessary to call ShouldSendProbe before that.
	Start(maxPacketSize protocol.ByteCount)
	ShouldSendProbe(now time.Time) bool
	CurrentSize() protocol.ByteCount
	GetPing() (ping ackhandler.Frame, datagramSize protocol.ByteCount)
}

const (
	// At some point, we have to stop searching for a higher MTU.
	// We're happy to send a packet that's 10 bytes smaller than the actual MTU.
	maxMTUDiff = 20
	// send a probe packet every mtuProbeDelay RTTs
	mtuProbeDelay = 5
)

func getMaxPacketSize(addr net.Addr) protocol.ByteCount {
	maxSize := protocol.ByteCount(protocol.MinInitialPacketSize)
	// If this is not a UDP address, we don't know anything about the MTU.
	// Use the minimum size of an Initial packet as the max packet size.
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if utils.IsIPv4(udpAddr.IP) {
			maxSize = protocol.InitialPacketSizeIPv4
		} else {
			maxSize = protocol.InitialPacketSizeIPv6
		}
	}
	return maxSize
}

type mtuFinder struct {
	lastProbeTime time.Time
	probeInFlight bool
	mtuIncreased  func(protocol.ByteCount)

	rttStats *utils.RTTStats
	current  protocol.ByteCount
	max      protocol.ByteCount // the maximum value, as advertised by the peer (or our maximum size buffer)
}

var _ mtuDiscoverer = &mtuFinder{}

func newMTUDiscoverer(rttStats *utils.RTTStats, start protocol.ByteCount, mtuIncreased func(protocol.ByteCount)) *mtuFinder {
	return &mtuFinder{
		current:      start,
		rttStats:     rttStats,
		mtuIncreased: mtuIncreased,
	}
}

func (f *mtuFinder) done() bool {
	return f.max-f.current <= maxMTUDiff+1
}

func (f *mtuFinder) Start(maxPacketSize protocol.ByteCount) {
	f.lastProbeTime = time.Now() // makes sure the first probe packet is not sent immediately
	f.max = maxPacketSize
}

func (f *mtuFinder) ShouldSendProbe(now time.Time) bool {
	if f.max == 0 || f.lastProbeTime.IsZero() {
		return false
	}
	if f.probeInFlight || f.done() {
		return false
	}
	return !now.Before(f.lastProbeTime.Add(mtuProbeDelay * f.rttStats.SmoothedRTT()))
}

func (f *mtuFinder) GetPing() (ackhandler.Frame, protocol.ByteCount) {
	size := (f.max + f.current) / 2
	f.lastProbeTime = time.Now()
	f.probeInFlight = true
	return ackhandler.Frame{
		Frame: &wire.PingFrame{},
		OnLost: func(wire.Frame) {
			f.probeInFlight = false
			f.max = size
		},
		OnAcked: func(wire.Frame) {
			f.probeInFlight = false
			f.current = size
			f.mtuIncreased(size)
		},
	}, size
}

func (f *mtuFinder) CurrentSize() protocol.ByteCount {
	return f.current
}
