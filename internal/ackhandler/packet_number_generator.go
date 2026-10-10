package ackhandler

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

type packetNumberGenerator interface {
	Peek() protocol.PacketNumber
	// Pop pops the packet number.
	// It reports if the packet number (before the one just popped) was skipped.
	// It never skips more than one packet number in a row.
	Pop() (skipped bool, _ protocol.PacketNumber)
}

type sequentialPacketNumberGenerator struct {
	next protocol.PacketNumber
}

var _ packetNumberGenerator = &sequentialPacketNumberGenerator{}

func newSequentialPacketNumberGenerator(initial protocol.PacketNumber) packetNumberGenerator {
	return &sequentialPacketNumberGenerator{next: initial}
}

func (p *sequentialPacketNumberGenerator) Peek() protocol.PacketNumber {
	return p.next
}

func (p *sequentialPacketNumberGenerator) Pop() (bool, protocol.PacketNumber) {
	next := p.next
	p.next++
	return false, next
}

const (
	// skipPacketInitialPeriod is the initial period length used for packet number skipping
	// to prevent an Optimistic ACK attack.
	// Every time a packet number is skipped, the period is doubled, up to skipPacketMaxPeriod.
	skipPacketInitialPeriod = 256

	// skipPacketMaxPeriod is the maximum period length used for packet number skipping.
	skipPacketMaxPeriod = 128 * 1024
)

// The skippingPacketNumberGenerator generates the packet number for the next packet
// it randomly skips a packet number every averagePeriod packets (on average).
// It is guaranteed to never skip two consecutive packet numbers.
type skippingPacketNumberGenerator struct {
	next protocol.PacketNumber

	period           uint32
	maxPeriod        uint32
	packetsUntilSkip uint32

	rng utils.Rand
}

var _ packetNumberGenerator = &skippingPacketNumberGenerator{}

func newSkippingPacketNumberGenerator(initial protocol.PacketNumber, initialPeriod, maxPeriod uint32) packetNumberGenerator {
	g := &skippingPacketNumberGenerator{
		next:      initial,
		period:    initialPeriod,
		maxPeriod: maxPeriod,
	}
	g.generateNewSkip()
	return g
}

func (p *skippingPacketNumberGenerator) Peek() protocol.PacketNumber {
	if p.packetsUntilSkip == 0 {
		return p.next + 1
	}
	return p.next
}

func (p *skippingPacketNumberGenerator) Pop() (bool, protocol.PacketNumber) {
	next := p.next
	if p.packetsUntilSkip == 0 {
		next++
		p.next += 2
		p.generateNewSkip()
		return true, next
	}
	p.packetsUntilSkip--
	p.next++ // generate a new packet number for the next packet
	return false, next
}

func (p *skippingPacketNumberGenerator) generateNewSkip() {
	// make sure that there are never two consecutive packet numbers that are skipped
	p.packetsUntilSkip = 3 + p.rng.Uint32N(2*p.period)
	p.period = min(2*p.period, p.maxPeriod)
}
