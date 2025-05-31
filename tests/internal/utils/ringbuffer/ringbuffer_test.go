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
	require.Equal(t, 3, r.PopFront())
	require.Equal(t, 4, r.PopFront())
	require.Equal(t, 5, r.PopFront())
	require.Equal(t, 6, r.PopFront())
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
	require.True(t, r.full)
	r.Clear()
	require.False(t, r.full)
	require.Equal(t, 0, r.Len())
}
