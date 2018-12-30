package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type packetBuffer struct {
	Slice []byte

	// refCount counts how many packets the Slice is used in.
	// It doesn't support concurrent use.
	// It is > 1 when used for coalesced packet.
	refCount int
}

// Split increases the refCount.
// It must be called when a packet buffer is used for more than one packet,
// e.g. when splitting coalesced packets.
func (b *packetBuffer) Split() {
	b.refCount++
}

// Release decreases the refCount.
// It should be called when processing the packet is finished.
// When the refCount reaches 0, the packet buffer is put back into the pool.
func (b *packetBuffer) Release() {
	if cap(b.Slice) != int(protocol.MaxReceivePacketSize) {
		panic("putPacketBuffer called with packet of wrong size!")
	}
	b.refCount--
	if b.refCount < 0 {
		panic("negative packetBuffer refCount")
	}
	// only put the packetBuffer back if it's not used any more
	if b.refCount == 0 {
		bufferPool.Put(b)
	}
}

var bufferPool sync.Pool

func getPacketBuffer() *packetBuffer {
	buf := bufferPool.Get().(*packetBuffer)
	buf.refCount = 1
	buf.Slice = buf.Slice[:protocol.MaxReceivePacketSize]
	return buf
}

func init() {
	bufferPool.New = func() interface{} {
		return &packetBuffer{
			Slice: make([]byte, 0, protocol.MaxReceivePacketSize),
		}
	}
}
