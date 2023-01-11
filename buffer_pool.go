package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// BufferPool allows setting custom pools for reading and writing buffers.
type BufferPool interface {
	// New obtains an unused buffer that must not be used until Release is
	// called onto it. You can supply a tag to uniquely identify the buffer
	// for accounting purposes.
	New(size int) ([]byte, int)

	// Release marks the buffer tagged with tag as not used.
	Release(tag int, buf []byte)
}

type BufferPoolConn interface {
	BufferPool() BufferPool
}

type packetBufferPool struct {
	pool BufferPool
}

func (p *packetBufferPool) getPacketBuffer() *packetBuffer {
	packet := packetPool.Get().(*packetBuffer)
	packet.refCount = 1

	if p == nil {
		packet.Data = defaultPacketBufferPool.Get().([]byte)
		packet.Tag = -1
	} else {
		packet.Data, packet.Tag = p.pool.New(int(protocol.MaxPacketBufferSize))
		packet.pool = p.pool
	}

	return packet
}

type packetBuffer struct {
	Data []byte
	Tag  int

	pool BufferPool

	// refCount counts how many packets Data is used in.
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

// Decrement decrements the reference counter.
// It doesn't put the buffer back into the pool.
func (b *packetBuffer) Decrement() {
	b.refCount--
	if b.refCount < 0 {
		panic("negative packetBuffer refCount")
	}
}

// MaybeRelease puts the packet buffer back into the pool,
// if the reference counter already reached 0.
func (b *packetBuffer) MaybeRelease() {
	// only put the packetBuffer back if it's not used any more
	if b.refCount == 0 {
		b.putBack()
	}
}

// Release puts back the packet buffer into the pool.
// It should be called when processing is definitely finished.
func (b *packetBuffer) Release() {
	b.Decrement()
	if b.refCount != 0 {
		panic("packetBuffer refCount not zero")
	}
	b.putBack()
}

// Len returns the length of Data
func (b *packetBuffer) Len() protocol.ByteCount {
	return protocol.ByteCount(len(b.Data))
}

func (b *packetBuffer) putBack() {
	if cap(b.Data) != int(protocol.MaxPacketBufferSize) {
		panic("putPacketBuffer called with packet of wrong size!")
	}
	if b.pool != nil {
		b.pool.Release(b.Tag, b.Data)
	}
	packetPool.Put(b)
}

var packetPool sync.Pool
var defaultPacketBufferPool sync.Pool

func init() {
	packetPool.New = func() interface{} {
		return &packetBuffer{}
	}

	defaultPacketBufferPool.New = func() interface{} {
		return make([]byte, 0, int(protocol.MaxPacketBufferSize))
	}
}
