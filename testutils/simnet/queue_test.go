package simnet

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQueue(t *testing.T) {
	q := newQueue()
	baseTime := time.Now()

	// Enqueue 5 packets with different delivery times
	// Two packets scheduled for the same time (t2)
	p1 := &packetWithDeliveryTime{
		Packet:       Packet{Data: []byte("packet1")},
		DeliveryTime: baseTime.Add(10 * time.Millisecond),
	}
	p2 := &packetWithDeliveryTime{
		Packet:       Packet{Data: []byte("packet2")},
		DeliveryTime: baseTime.Add(20 * time.Millisecond),
	}
	p3 := &packetWithDeliveryTime{
		Packet:       Packet{Data: []byte("packet3")},
		DeliveryTime: baseTime.Add(20 * time.Millisecond), // Same time as p2
	}
	p4 := &packetWithDeliveryTime{
		Packet:       Packet{Data: []byte("packet4")},
		DeliveryTime: baseTime.Add(30 * time.Millisecond),
	}
	p5 := &packetWithDeliveryTime{
		Packet:       Packet{Data: []byte("packet5")},
		DeliveryTime: baseTime.Add(5 * time.Millisecond),
	}

	// Enqueue in non-chronological order
	q.Enqueue(p1)
	q.Enqueue(p2)
	q.Enqueue(p3)
	q.Enqueue(p4)
	q.Enqueue(p5)

	// Dequeue should return packets in order: p5, p1, p2, p3, p4
	// p2 and p3 have same time, but p2 was enqueued first
	received, ok := q.Dequeue()
	require.True(t, ok)
	require.Equal(t, "packet5", string(received.Data))

	received, ok = q.Dequeue()
	require.True(t, ok)
	require.Equal(t, "packet1", string(received.Data))

	received, ok = q.Dequeue()
	require.True(t, ok)
	require.Equal(t, "packet2", string(received.Data))

	received, ok = q.Dequeue()
	require.True(t, ok)
	require.Equal(t, "packet3", string(received.Data))

	received, ok = q.Dequeue()
	require.True(t, ok)
	require.Equal(t, "packet4", string(received.Data))
}

func TestQueueClose(t *testing.T) {
	q := newQueue()
	q.Close()

	_, ok := q.Dequeue()
	require.False(t, ok)

	// enqueue after close should be ignored
	p := &packetWithDeliveryTime{
		Packet:       Packet{Data: []byte("packet")},
		DeliveryTime: time.Now(),
	}
	q.Enqueue(p)
	// dequeue should still return false
	_, ok = q.Dequeue()
	require.False(t, ok)
}
