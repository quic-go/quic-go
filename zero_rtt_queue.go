package quic

import (
	"sync"

	"github.com/benbjohnson/clock"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type zeroRTTQueueEntry struct {
	timer   *clock.Timer
	packets []*receivedPacket
}

type zeroRTTQueue struct {
	clock clock.Clock

	mutex sync.Mutex
	queue map[string]*zeroRTTQueueEntry
}

func newZeroRTTQueue(clock clock.Clock) *zeroRTTQueue {
	return &zeroRTTQueue{
		clock: clock,
		queue: make(map[string]*zeroRTTQueueEntry),
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
		h.queue[cid] = &zeroRTTQueueEntry{timer: h.clock.AfterFunc(protocol.Max0RTTQueueingDuration, func() {
			h.deleteQueue(connID)
		})}
	}
	entry := h.queue[cid]
	if len(entry.packets) >= protocol.Max0RTTQueueLen {
		return
	}
	entry.packets = append(entry.packets, p)
}

func (h *zeroRTTQueue) Dequeue(connID protocol.ConnectionID) *receivedPacket {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	entry, ok := h.queue[string(connID)]
	if !ok {
		return nil
	}
	p := entry.packets[0]
	entry.packets = entry.packets[1:]
	if len(entry.packets) == 0 {
		entry.timer.Stop()
		delete(h.queue, string(connID))
	}
	return p
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
