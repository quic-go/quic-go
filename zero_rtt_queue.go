package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type zeroRTTQueue struct {
	mutex sync.Mutex
	queue map[string][]*receivedPacket
}

func newZeroRTTQueue() *zeroRTTQueue {
	return &zeroRTTQueue{queue: make(map[string][]*receivedPacket)}
}

func (h *zeroRTTQueue) Enqueue(connID protocol.ConnectionID, p *receivedPacket) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	cid := string(connID)
	if _, ok := h.queue[cid]; !ok && len(h.queue) >= protocol.Max0RTTQueues {
		return
	}
	if len(h.queue[cid]) >= protocol.Max0RTTQueueLen {
		return
	}
	h.queue[cid] = append(h.queue[cid], p)
}

func (h *zeroRTTQueue) Dequeue(connID protocol.ConnectionID) *receivedPacket {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	cid := string(connID)
	if _, ok := h.queue[cid]; !ok {
		return nil
	}
	p := h.queue[cid][0]
	h.queue[cid] = h.queue[cid][1:]
	if len(h.queue[cid]) == 0 {
		delete(h.queue, cid)
	}
	return p
}
