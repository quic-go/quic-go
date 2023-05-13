package quic

import (
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
)

type receiveQueue struct {
	mx        sync.Mutex
	receiving []*receivedPacket

	readPos int
	reading []*receivedPacket

	c          chan struct{}
	hasPackets atomic.Bool

	tracer logging.ConnectionTracer
}

func newReceiveQueue(tracer logging.ConnectionTracer) *receiveQueue {
	const initialCap = 16
	return &receiveQueue{
		receiving: make([]*receivedPacket, 0, initialCap),
		reading:   make([]*receivedPacket, 0, initialCap),
		c:         make(chan struct{}, 1),
		tracer:    tracer,
	}
}

func (q *receiveQueue) Chan() chan struct{} {
	return q.c
}

func (q *receiveQueue) HasPackets() bool {
	return q.hasPackets.Load()
}

func (q *receiveQueue) Add(p *receivedPacket) {
	var drop bool

	q.mx.Lock()
	// TODO: add comment how enlarging works
	if len(q.receiving) < protocol.MaxConnUnprocessedPackets {
		q.receiving = append(q.receiving, p)
	} else {
		drop = true
	}
	q.mx.Unlock()

	if drop && q.tracer != nil {
		q.tracer.DroppedPacket(logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropDOSPrevention)
		return
	}
	q.hasPackets.Store(true)
	select {
	case q.c <- struct{}{}:
	default:
	}
}

func (q *receiveQueue) Pop() *receivedPacket {
	// Fast path (lock-free!).
	// We still have outstanding packets in the reading queue.
	if q.readPos < len(q.reading) {
		p := q.reading[q.readPos]
		q.reading[q.readPos] = nil
		q.readPos++

		select {
		case q.c <- struct{}{}:
		default:
		}
		return p
	}
	// We've finished the reading queue.
	// Grab the receiving queue, if it has packets.
	q.mx.Lock()
	if len(q.receiving) == 0 { // nothing more to read
		q.mx.Unlock()
		q.hasPackets.Store(false)
		return nil
	}
	q.reading = q.reading[:0]
	q.reading, q.receiving = q.receiving, q.reading
	q.readPos = 0
	q.mx.Unlock()
	return q.Pop()
}
