package simnet

import (
	"math"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
)

const (
	codelTarget       = 5 * time.Millisecond
	codelInterval     = 100 * time.Millisecond
	codelLimitPackets = 1000 // the default limit of Linux's codel qdisc
)

type codelPacket struct {
	Packet
	enqueued time.Time
}

// codelQueue is a FIFO queue managed by CoDel (RFC 8289).
// Like Linux, it marks ECN-capable packets CE instead of dropping them.
type codelQueue struct {
	mtu int

	mu        sync.Mutex
	packets   []codelPacket
	closed    bool
	newPacket chan struct{}

	// CoDel state, named as in RFC 8289
	firstAboveTime time.Time
	dropNext       time.Time
	count          int
	lastCount      int
	dropping       bool
}

func newCodelQueue(mtu int) *codelQueue {
	return &codelQueue{
		mtu:       mtu,
		newPacket: make(chan struct{}, 1),
	}
}

// Enqueue adds a packet to the queue. It drops the packet if the queue is full.
func (q *codelQueue) Enqueue(p Packet) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed || len(q.packets) >= codelLimitPackets {
		return
	}
	q.packets = append(q.packets, codelPacket{Packet: p, enqueued: time.Now()})

	select {
	case q.newPacket <- struct{}{}:
	default:
	}
}

// Dequeue blocks until a packet can be sent.
// It returns net.ErrClosed once the queue is closed.
func (q *codelQueue) Dequeue() (Packet, error) {
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return Packet{}, net.ErrClosed
		}
		var p *Packet
		if len(q.packets) > 0 {
			p = q.dequeue(time.Now())
		}
		q.mu.Unlock()
		if p != nil {
			return *p, nil
		}
		<-q.newPacket
	}
}

// Close unblocks Dequeue.
func (q *codelQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.closed = true
	close(q.newPacket)
}

// dequeue is RFC 8289's dequeue(). It returns nil if the queue is empty.
func (q *codelQueue) dequeue(now time.Time) *Packet {
	p, okToDrop := q.doDequeue(now)
	if q.dropping {
		if !okToDrop {
			// sojourn time below target: leave the dropping state
			q.dropping = false
		}
		// Time for the next drop. Drop the current packet and dequeue the next.
		// If that doesn't end the dropping state, schedule the next drop.
		// A large backlog might need several drops at once, hence the loop.
		for !now.Before(q.dropNext) && q.dropping {
			q.count++
			if isECNCapable(p.ECN) {
				p.ECN = protocol.ECNCE
				q.dropNext = codelControlLaw(q.dropNext, q.count)
				return p
			}
			p, okToDrop = q.doDequeue(now)
			if okToDrop {
				q.dropNext = codelControlLaw(q.dropNext, q.count)
			} else {
				q.dropping = false
			}
		}
		return p
	}
	if !okToDrop {
		return p
	}
	// The sojourn time has been above the target for an interval: enter the dropping state.
	if isECNCapable(p.ECN) {
		p.ECN = protocol.ECNCE
	} else {
		p, _ = q.doDequeue(now)
	}
	q.dropping = true
	// If the sojourn time went above the target shortly after it last went below,
	// start from the drop rate that controlled the queue then.
	delta := q.count - q.lastCount
	q.count = 1
	if delta > 1 && now.Sub(q.dropNext) < 16*codelInterval {
		q.count = delta
	}
	q.dropNext = codelControlLaw(now, q.count)
	q.lastCount = q.count
	return p
}

// doDequeue is RFC 8289's dodequeue(). It returns nil if the queue is empty,
// and reports whether the sojourn time has been above the target for at least an interval.
func (q *codelQueue) doDequeue(now time.Time) (*Packet, bool) {
	if len(q.packets) == 0 {
		// queue is empty: we can't be above the target
		q.firstAboveTime = time.Time{}
		return nil, false
	}
	p := q.packets[0]
	q.packets = q.packets[1:]

	var queuedBytes int
	for _, p := range q.packets {
		queuedBytes += len(p.Data)
	}

	if now.Sub(p.enqueued) < codelTarget || queuedBytes <= q.mtu {
		// went below: stay below for at least an interval
		q.firstAboveTime = time.Time{}
		return &p.Packet, false
	}
	if q.firstAboveTime.IsZero() {
		// just went above: if still above at firstAboveTime, it's ok to drop
		q.firstAboveTime = now.Add(codelInterval)
		return &p.Packet, false
	}
	return &p.Packet, !now.Before(q.firstAboveTime)
}

func codelControlLaw(t time.Time, count int) time.Time {
	return t.Add(time.Duration(float64(codelInterval) / math.Sqrt(float64(count))))
}

func isECNCapable(ecn protocol.ECN) bool {
	return ecn == protocol.ECT0 || ecn == protocol.ECT1 || ecn == protocol.ECNCE
}
