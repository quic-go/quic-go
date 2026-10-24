package quic

import (
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
)

// A sidePacket is a packet received on a Transport other than the one of the active path.
type sidePacket struct {
	receivedPacket
	source packetHandler
}

// The receivedPacketQueue queues received packets until they are processed by the connection's run loop.
// Packets are identified by the packetHandler that the Transport passed them to, i.e. by the Transport they were received on.
// Packets received on the Transport of the active path are queued in the main queue.
// Packets received on any other Transport are queued in the side queue.
// The side queue is only used by clients that probe or migrate to new paths.
type receivedPacketQueue struct {
	mx     sync.Mutex
	active packetHandler
	main   ringbuffer.RingBuffer[receivedPacket]
	side   ringbuffer.RingBuffer[sidePacket] // only allocated once a packet is received on a different Transport
}

// Init initializes the queue.
// The active packetHandler is the one of the Transport that the connection was created on.
func (q *receivedPacketQueue) Init(active packetHandler) {
	q.main.Init(8)
	q.active = active
}

// Push queues a packet received by the packetHandler source.
// It returns false if the packet was dropped because too many packets are queued.
func (q *receivedPacketQueue) Push(p receivedPacket, source packetHandler) bool {
	q.mx.Lock()
	defer q.mx.Unlock()

	if source == q.active {
		if q.main.Len() >= protocol.MaxConnUnprocessedPackets {
			return false
		}
		q.main.PushBack(p)
		return true
	}

	if q.side.Len() >= protocol.MaxConnUnprocessedPackets {
		return false
	}
	q.side.PushBack(sidePacket{receivedPacket: p, source: source})
	return true
}

// Pop returns the next packet, and the packetHandler that received it.
// Packets in the side queue are returned first:
// When switching paths, the packets received on the old path are moved to the side queue.
func (q *receivedPacketQueue) Pop() (_ receivedPacket, source packetHandler, ok bool) {
	q.mx.Lock()
	defer q.mx.Unlock()

	if !q.side.Empty() {
		p := q.side.PopFront()
		return p.receivedPacket, p.source, true
	}
	if !q.main.Empty() {
		return q.main.PopFront(), q.active, true
	}
	return receivedPacket{}, nil, false
}

func (q *receivedPacketQueue) Empty() bool {
	q.mx.Lock()
	defer q.mx.Unlock()

	return q.main.Empty() && q.side.Empty()
}

// SetActive is called when switching paths.
// It moves packets queued for the old path to the side queue.
func (q *receivedPacketQueue) SetActive(active packetHandler) {
	q.mx.Lock()
	defer q.mx.Unlock()

	if active == q.active {
		return
	}
	for !q.main.Empty() {
		q.side.PushBack(sidePacket{receivedPacket: q.main.PopFront(), source: q.active})
	}
	q.active = active
}

// Clear drops all queued packets.
func (q *receivedPacketQueue) Clear() {
	q.mx.Lock()
	defer q.mx.Unlock()

	for !q.main.Empty() {
		p := q.main.PopFront()
		p.buffer.Decrement()
		p.buffer.MaybeRelease()
	}
	for !q.side.Empty() {
		p := q.side.PopFront()
		p.buffer.Decrement()
		p.buffer.MaybeRelease()
	}
}
