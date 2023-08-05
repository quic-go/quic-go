package ringbuffer

import "testing"

func BenchmarkRingBuffer(b *testing.B) {
	r := RingBuffer[int]{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.PushBack(i)
		r.PopFront()
	}
}
