package simnet

import (
	"container/heap"
	"math"
	"sync"
	"time"
)

// codelQueue is a FIFO queue with CoDel bufferbloat control
type codelQueue struct {
	mu        sync.Mutex
	packets   packetHeap
	newPacket chan struct{}
	closed    bool
	pushCount int

	// CoDel state
	dropping     bool
	firstAbove   time.Time
	dropNext     time.Time
	count        int
	target       time.Duration // target queue delay (e.g., 5ms)
	interval     time.Duration // interval for sustained bad queue (e.g., 100ms)
	lastDropTime time.Time
}

func newCodelQueue(target, interval time.Duration) *codelQueue {
	q := &codelQueue{
		target:    target,
		interval:  interval,
		newPacket: make(chan struct{}, 1),
	}
	heap.Init(&q.packets)
	return q
}

// Enqueue adds a packet to the queue
func (q *codelQueue) Enqueue(p *packetWithDeliveryTime) {
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
func (q *codelQueue) Dequeue() (*packetWithDeliveryTime, bool) {
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
			// No packets, wait for one to arrive
			q.mu.Unlock()
			select {
			case <-q.newPacket:
				timer.Stop()
				continue
			case <-timer.C:
				continue
			}
		}

		earliest := q.packets[0]
		earliestTime := earliest.DeliveryTime

		now := time.Now()
		if now.Before(earliestTime) {
			// Not ready yet, wait until delivery time or new packet
			waitDuration := earliestTime.Sub(now)
			timer.Reset(waitDuration)
			q.mu.Unlock()

			select {
			case <-timer.C:
				// Timer expired, check again
				continue
			case <-q.newPacket:
				// New packet arrived, might have earlier delivery time
				timer.Stop()
				continue
			}
		}

		// Packet is ready, remove from queue and return it
		po := heap.Pop(&q.packets).(packetWithDeliveryTimeAndOrder)
		p := po.packetWithDeliveryTime

		// Reset CoDel state when queue becomes empty
		if len(q.packets) == 0 {
			q.dropping = false
			q.firstAbove = time.Time{}
		}

		q.mu.Unlock()

		return p, true
	}
}

// shouldDrop implements the CoDel dropping decision (thread-safe version)
func (q *codelQueue) shouldDrop(sojournTime time.Duration) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.codelShouldDrop(sojournTime, time.Now())
}

// codelShouldDrop implements the CoDel dropping decision
func (q *codelQueue) codelShouldDrop(sojournTime time.Duration, now time.Time) bool {
	// Reset CoDel state when queue is empty (checked by caller before dequeue)
	// This is handled by resetting state when queue becomes empty in Dequeue

	if sojournTime < q.target {
		// Queue is good, reset state
		q.firstAbove = time.Time{}
		q.dropping = false
		return false
	}

	// Queue delay is above target
	if q.firstAbove.IsZero() {
		// First time above target, start tracking
		q.firstAbove = now.Add(q.interval)
		return false
	}

	if now.Before(q.firstAbove) {
		// Haven't been above target for long enough
		return false
	}

	// We've been above target for the full interval
	if !q.dropping {
		// Enter dropping state
		q.dropping = true
		q.count = 1
		q.dropNext = now
		q.lastDropTime = now
		return true
	}

	// Already in dropping state
	if now.After(q.dropNext) {
		// Time to drop another packet
		q.count++
		// Calculate next drop time using control law: interval / sqrt(count)
		delta := time.Duration(float64(q.interval) / math.Sqrt(float64(q.count)))
		q.dropNext = now.Add(delta)
		q.lastDropTime = now
		return true
	}

	return false
}

// Close closes the queue
func (q *codelQueue) Close() {
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
	return (h[i].DeliveryTime.Before(h[j].DeliveryTime) ||
		h[i].DeliveryTime.Equal(h[j].DeliveryTime) && h[i].count < h[j].count)
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
