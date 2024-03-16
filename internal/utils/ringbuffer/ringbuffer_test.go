package ringbuffer

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RingBuffer", func() {
	It("push, peek and pop", func() {
		r := RingBuffer[int]{}
		Expect(len(r.ring)).To(Equal(0))
		Expect(func() { r.PopFront() }).To(Panic())
		r.PushBack(1)
		r.PushBack(2)
		r.PushBack(3)
		Expect(r.PeekFront()).To(Equal(1))
		Expect(r.PeekFront()).To(Equal(1))
		Expect(r.PopFront()).To(Equal(1))
		Expect(r.PeekFront()).To(Equal(2))
		Expect(r.PopFront()).To(Equal(2))
		r.PushBack(4)
		r.PushBack(5)
		Expect(r.Len()).To(Equal(3))
		r.PushBack(6)
		Expect(r.Len()).To(Equal(4))
		Expect(r.PopFront()).To(Equal(3))
		Expect(r.PopFront()).To(Equal(4))
		Expect(r.PopFront()).To(Equal(5))
		Expect(r.PopFront()).To(Equal(6))
	})

	It("panics when Peek or Pop are called on an empty buffer", func() {
		r := RingBuffer[string]{}
		Expect(r.Empty()).To(BeTrue())
		Expect(r.Len()).To(BeZero())
		Expect(func() { r.PeekFront() }).To(Panic())
		Expect(func() { r.PopFront() }).To(Panic())
	})

	It("clearing", func() {
		r := RingBuffer[int]{}
		r.Init(2)
		r.PushBack(1)
		r.PushBack(2)
		Expect(r.full).To(BeTrue())
		r.Clear()
		Expect(r.full).To(BeFalse())
		Expect(r.Len()).To(Equal(0))
	})
})
