package ringbuffer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPushPeekPop(t *testing.T) {
	r := RingBuffer[int]{}
	require.Equal(t, 0, len(r.ring))
	require.Panics(t, func() { r.PopFront() })
	r.PushBack(1)
	r.PushBack(2)
	r.PushBack(3)
	require.Equal(t, 1, r.PeekFront())
	require.Equal(t, 1, r.PeekFront())
	require.Equal(t, 1, r.PopFront())
	require.Equal(t, 2, r.PeekFront())
	require.Equal(t, 2, r.PopFront())
	r.PushBack(4)
	r.PushBack(5)
	require.Equal(t, 3, r.Len())
	r.PushBack(6)
	require.Equal(t, 4, r.Len())
	r.PushBack(7) // grow with the buffer wrapped around
	require.Equal(t, 5, r.Len())
	require.Equal(t, 3, r.PopFront())
	require.Equal(t, 4, r.PopFront())
	require.Equal(t, 5, r.PopFront())
	require.Equal(t, 6, r.PopFront())
	require.Equal(t, 7, r.PopFront())
}

func TestPanicOnEmptyBuffer(t *testing.T) {
	r := RingBuffer[string]{}
	require.True(t, r.Empty())
	require.Zero(t, r.Len())
	require.Panics(t, func() { r.PeekFront() })
	require.Panics(t, func() { r.PopFront() })
}

func TestClear(t *testing.T) {
	r := RingBuffer[int]{}
	r.Init(2)
	r.PushBack(1)
	r.PushBack(2)
	require.Equal(t, 2, r.Len())
	r.Clear()
	require.True(t, r.Empty())
	r.PushBack(3)
	require.Equal(t, 3, r.PopFront())
}

func BenchmarkRingBuffer(b *testing.B) {
	r := RingBuffer[int]{}

	var val int
	for b.Loop() {
		r.PushBack(val)
		r.PopFront()
		val++
	}
}

func BenchmarkRingBufferWrapped(b *testing.B) {
	var r RingBuffer[int]
	r.Init(32)
	for i := range 16 {
		r.PushBack(i)
	}

	var val int
	for b.Loop() {
		r.PushBack(val)
		val = r.PopFront()
	}
}
