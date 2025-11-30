package simnet

import (
	"container/heap"
	"sync"
	"time"
)

// queue is a priority queue that delivers packets at their scheduled delivery time
type queue struct {
	mu        sync.Mutex
	packets   packetHeap
	newPacket chan struct{}
	closed    bool
	pushCount int
}

func newQueue() *queue {
	q := &queue{
		newPacket: make(chan struct{}, 1),
	}
	heap.Init(&q.packets)
	return q
}

// Enqueue adds a packet to the queue
func (q *queue) Enqueue(p *packetWithDeliveryTime) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.pushCount++
	heap.Push(&q.packets, packetWithDeliveryTimeAndOrder{packetWithDeliveryTime: p, count: q.pushCount})

	// Signal that a new packet arrived (non-blocking)
	select {
	case q.newPacket <- struct{}{}:
	default:
	}
}

// Dequeue removes and returns the next packet when it's ready for delivery
// This blocks until a packet is available AND its delivery time has been reached
// Uses a timer that can be reset if a packet with earlier delivery time arrives
func (q *queue) Dequeue() (*packetWithDeliveryTime, bool) {
	timer := time.NewTimer(time.Hour)
	timer.Stop()

	for {
		q.mu.Lock()

		if q.closed {
			q.mu.Unlock()
			timer.Stop()
			return nil, false
		}

		if len(q.packets) == 0 {
			// no packets, wait for one to arrive
			q.mu.Unlock()
			<-q.newPacket
			timer.Stop()
			continue
		}

		earliest := q.packets[0]
		earliestTime := earliest.DeliveryTime

		now := time.Now()
		if now.Before(earliestTime) {
			// not ready yet, wait until delivery time or new packet
			waitDuration := earliestTime.Sub(now)
			timer.Reset(waitDuration)
			q.mu.Unlock()

			select {
			case <-timer.C:
				continue
			case <-q.newPacket:
				// new packet arrived, might have earlier delivery time
				timer.Stop()
				continue
			}
		}

		// Packet is ready, remove from queue and return it
		po := heap.Pop(&q.packets).(packetWithDeliveryTimeAndOrder)
		p := po.packetWithDeliveryTime

		q.mu.Unlock()

		return p, true
	}
}

// Close closes the queue
func (q *queue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.closed = true
	close(q.newPacket)
}

type packetWithDeliveryTimeAndOrder struct {
	count int
	*packetWithDeliveryTime
}

// packetHeap implements heap.Interface ordered by packet delivery time.
type packetHeap []packetWithDeliveryTimeAndOrder

func (h packetHeap) Len() int { return len(h) }

func (h packetHeap) Less(i, j int) bool {
	return (h[i].DeliveryTime.Before(h[j].DeliveryTime) || h[i].DeliveryTime.Equal(h[j].DeliveryTime) && h[i].count < h[j].count)
}

func (h packetHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *packetHeap) Push(x any) {
	*h = append(*h, x.(packetWithDeliveryTimeAndOrder))
}

func (h *packetHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}
