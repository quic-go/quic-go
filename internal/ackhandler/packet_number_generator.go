package ackhandler

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// The packetNumberGenerator generates the packet number for the next packet
// it randomly skips a packet number every averagePeriod packets (on average).
// It is guaranteed to never skip two consecutive packet numbers.
type packetNumberGenerator struct {
	rand          *mrand.Rand
	averagePeriod protocol.PacketNumber

	next       protocol.PacketNumber
	nextToSkip protocol.PacketNumber
}

func newPacketNumberGenerator(initial, averagePeriod protocol.PacketNumber) *packetNumberGenerator {
	b := make([]byte, 8)
	rand.Read(b) // it's not the end of the world if we don't get perfect random here
	g := &packetNumberGenerator{
		rand:          mrand.New(mrand.NewSource(int64(binary.LittleEndian.Uint64(b)))),
		next:          initial,
		averagePeriod: averagePeriod,
	}
	g.generateNewSkip()
	return g
}

func (p *packetNumberGenerator) Peek() protocol.PacketNumber {
	return p.next
}

func (p *packetNumberGenerator) Pop() protocol.PacketNumber {
	next := p.next

	// generate a new packet number for the next packet
	p.next++

	if p.next == p.nextToSkip {
		p.next++
		p.generateNewSkip()
	}
	return next
}

func (p *packetNumberGenerator) generateNewSkip() {
	// make sure that there are never two consecutive packet numbers that are skipped
	p.nextToSkip = p.next + 2 + protocol.PacketNumber(p.rand.Int31n(int32(2*p.averagePeriod)))
}
