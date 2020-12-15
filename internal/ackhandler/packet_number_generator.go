package ackhandler

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type packetNumberGenerator interface {
	Peek() protocol.PacketNumber
	Pop() protocol.PacketNumber
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

func (p *sequentialPacketNumberGenerator) Pop() protocol.PacketNumber {
	next := p.next
	p.next++
	return next
}

type rng struct {
	buf [4]byte
}

func (r *rng) Int31() int32 {
	rand.Read(r.buf[:])
	return int32(binary.BigEndian.Uint32(r.buf[:]) & ^uint32(1<<31))
}

// copied from the standard library math/rand implementation of Int63n
func (r *rng) Int31n(n int32) int32 {
	if n&(n-1) == 0 { // n is power of two, can mask
		return r.Int31() & (n - 1)
	}
	max := int32((1 << 31) - 1 - (1<<31)%uint32(n))
	v := r.Int31()
	for v > max {
		v = r.Int31()
	}
	return v % n
}

// The skippingPacketNumberGenerator generates the packet number for the next packet
// it randomly skips a packet number every averagePeriod packets (on average).
// It is guaranteed to never skip two consecutive packet numbers.
type skippingPacketNumberGenerator struct {
	period    protocol.PacketNumber
	maxPeriod protocol.PacketNumber

	next       protocol.PacketNumber
	nextToSkip protocol.PacketNumber

	rng rng
}

var _ packetNumberGenerator = &skippingPacketNumberGenerator{}

func newSkippingPacketNumberGenerator(initial, initialPeriod, maxPeriod protocol.PacketNumber) packetNumberGenerator {
	g := &skippingPacketNumberGenerator{
		next:      initial,
		period:    initialPeriod,
		maxPeriod: maxPeriod,
	}
	g.generateNewSkip()
	return g
}

func (p *skippingPacketNumberGenerator) Peek() protocol.PacketNumber {
	return p.next
}

func (p *skippingPacketNumberGenerator) Pop() protocol.PacketNumber {
	next := p.next
	p.next++ // generate a new packet number for the next packet
	if p.next == p.nextToSkip {
		p.next++
		p.generateNewSkip()
	}
	return next
}

func (p *skippingPacketNumberGenerator) generateNewSkip() {
	// make sure that there are never two consecutive packet numbers that are skipped
	p.nextToSkip = p.next + 2 + protocol.PacketNumber(p.rng.Int31n(int32(2*p.period)))
	p.period = utils.MinPacketNumber(2*p.period, p.maxPeriod)
}
