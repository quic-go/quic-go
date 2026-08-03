package minheap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHeap(t *testing.T) {
	var h Heap[int, string]
	require.True(t, h.Empty())
	require.Panics(t, func() { h.Peek() })
	require.Panics(t, func() { h.Pop() })

	h.Push(4, "four")
	h.Push(1, "one")
	h.Push(3, "three")
	h.Push(2, "two")
	require.Equal(t, 4, h.Len())
	key, value := h.Peek()
	require.Equal(t, 1, key)
	require.Equal(t, "one", value)
	for _, expected := range []struct {
		key   int
		value string
	}{{1, "one"}, {2, "two"}, {3, "three"}, {4, "four"}} {
		key, value = h.Pop()
		require.Equal(t, expected.key, key)
		require.Equal(t, expected.value, value)
	}
	require.True(t, h.Empty())

	h.Push(1, "one")
	h.Push(2, "two")
	h.Clear()
	require.True(t, h.Empty())
}
