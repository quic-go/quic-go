package simnet

import (
	"math/rand/v2"
	"testing"
	"time"
)

func BenchmarkCodelQueueEnqueueDequeue(b *testing.B) {
	const queueSize = 50000

	packets := make([]*packetWithDeliveryTime, queueSize)
	base := time.Now().Add(-time.Second)
	for i := range queueSize {
		packets[i] = &packetWithDeliveryTime{
			DeliveryTime: base.Add(time.Duration(i) * time.Microsecond),
		}
	}

	r := rand.New(rand.NewPCG(42, 42))
	r.Shuffle(queueSize, func(i, j int) {
		packets[i], packets[j] = packets[j], packets[i]
	})
	q := newCodelQueue(5*time.Millisecond, 100*time.Millisecond)
	for _, p := range packets {
		q.Enqueue(p)
	}

	i := 0
	for b.Loop() {
		q.Enqueue(packets[i])
		i = (i + 1) % queueSize

		pkt, ok := q.Dequeue()
		if !ok || pkt == nil {
			b.Fatal("unexpected empty dequeue")
		}
	}
}
