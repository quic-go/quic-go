package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type windowUpdateQueue struct {
	mutex sync.Mutex

	queue    map[protocol.StreamID]protocol.ByteCount
	callback func(wire.Frame)
}

func newWindowUpdateQueue(cb func(wire.Frame)) *windowUpdateQueue {
	return &windowUpdateQueue{
		queue:    make(map[protocol.StreamID]protocol.ByteCount),
		callback: cb,
	}
}

func (q *windowUpdateQueue) Add(stream protocol.StreamID, offset protocol.ByteCount) {
	q.mutex.Lock()
	q.queue[stream] = offset
	q.mutex.Unlock()
}

func (q *windowUpdateQueue) QueueAll() {
	q.mutex.Lock()
	for stream, offset := range q.queue {
		q.callback(&wire.MaxStreamDataFrame{
			StreamID:   stream,
			ByteOffset: offset,
		})
		delete(q.queue, stream)
	}
	q.mutex.Unlock()
}
