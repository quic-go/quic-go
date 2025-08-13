package ringbuffer

import "testing"

func BenchmarkRingBuffer(b *testing.B) {
	r := RingBuffer[int]{}

	var val int
	for b.Loop() {
		r.PushBack(val)
		r.PopFront()
		val++
	}
}
