package simnet

import "sync"

type packetQueue struct {
	byteCountLimit   int
	currentByteCount int
	queue            []packetWithDeliveryTime
	closed           bool
	cond             *sync.Cond
}

func newPacketQ(byteCountLimit int) *packetQueue {
	q := &packetQueue{
		byteCountLimit: byteCountLimit,
	}
	q.cond = sync.NewCond(&sync.Mutex{})
	return q
}

func (q *packetQueue) Close() {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()
	q.cond.Broadcast()
	q.closed = true
}

func (q *packetQueue) Push(p packetWithDeliveryTime) {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()
	if q.closed {
		return
	}
	if q.currentByteCount+len(p.Data) > q.byteCountLimit {
		return
	}
	q.queue = append(q.queue, p)
	q.currentByteCount += len(p.Data)
	q.cond.Signal()
}

func (q *packetQueue) Pop() (packetWithDeliveryTime, bool) {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()
	for len(q.queue) == 0 && !q.closed {
		// Block until a packet is added
		q.cond.Wait()
	}
	if q.closed {
		return packetWithDeliveryTime{}, false
	}
	p := q.queue[0]
	q.queue = q.queue[1:]
	q.currentByteCount -= len(p.Data)
	return p, true
}
