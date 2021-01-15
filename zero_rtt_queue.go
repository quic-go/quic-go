package quic

import (
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type zeroRTTQueueEntry struct {
	timer   *time.Timer
	packets []*receivedPacket
}

type zeroRTTQueue struct {
	mutex         sync.Mutex
	queue         map[string]*zeroRTTQueueEntry
	queueDuration time.Duration // so we can set it in tests
}

func newZeroRTTQueue() *zeroRTTQueue {
	return &zeroRTTQueue{
		queue:         make(map[string]*zeroRTTQueueEntry),
		queueDuration: protocol.Max0RTTQueueingDuration,
	}
}

func (h *zeroRTTQueue) Enqueue(connID protocol.ConnectionID, p *receivedPacket) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	cid := string(connID)
	if _, ok := h.queue[cid]; !ok {
		if len(h.queue) >= protocol.Max0RTTQueues {
			return
		}
		h.queue[cid] = &zeroRTTQueueEntry{timer: time.AfterFunc(h.queueDuration, func() {
			h.deleteQueue(connID)
		})}
	}
	entry := h.queue[cid]
	if len(entry.packets) >= protocol.Max0RTTQueueLen {
		return
	}
	entry.packets = append(entry.packets, p)
}

func (h *zeroRTTQueue) DequeueToSession(connID protocol.ConnectionID, sess packetHandler) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.dequeueToSession(connID, sess)
}

func (h *zeroRTTQueue) dequeueToSession(connID protocol.ConnectionID, sess packetHandler) {
	entry, ok := h.queue[string(connID)]
	if !ok {
		return
	}
	entry.timer.Stop()
	for _, p := range entry.packets {
		sess.handlePacket(p)
	}
	delete(h.queue, string(connID))
}

func (h *zeroRTTQueue) deleteQueue(connID protocol.ConnectionID) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	entry, ok := h.queue[string(connID)]
	if !ok {
		return
	}
	for _, p := range entry.packets {
		p.buffer.Release()
	}
	delete(h.queue, string(connID))
}
