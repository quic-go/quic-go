package quic

import (
	"sync"

	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

type windowUpdateQueue struct {
	mutex sync.Mutex

	queue map[protocol.StreamID]receiveStreamI

	connFlowController flowcontrol.ConnectionFlowController
	callback           func(wire.Frame)
}

func newWindowUpdateQueue(
	connFC flowcontrol.ConnectionFlowController,
	cb func(wire.Frame),
) *windowUpdateQueue {
	return &windowUpdateQueue{
		queue:              make(map[protocol.StreamID]receiveStreamI),
		connFlowController: connFC,
		callback:           cb,
	}
}

func (q *windowUpdateQueue) AddStream(id protocol.StreamID, str receiveStreamI) {
	q.mutex.Lock()
	q.queue[id] = str
	q.mutex.Unlock()
}

func (q *windowUpdateQueue) RemoveStream(id protocol.StreamID) {
	q.mutex.Lock()
	delete(q.queue, id)
	q.mutex.Unlock()
}

func (q *windowUpdateQueue) QueueAll() {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	// queue a connection-level window update
	if offset, ok := q.connFlowController.GetWindowUpdate(); ok {
		q.callback(&wire.MaxDataFrame{MaximumData: offset})
	}
	// queue all stream-level window updates
	for id, str := range q.queue {
		delete(q.queue, id)
		offset, ok := str.getWindowUpdate()
		if !ok { // can happen if we received a final offset, right after queueing the window update
			continue
		}
		q.callback(&wire.MaxStreamDataFrame{
			StreamID:          id,
			MaximumStreamData: offset,
		})
	}
}
