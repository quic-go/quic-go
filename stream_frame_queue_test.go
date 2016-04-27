package quic

import (
	"github.com/lucas-clemente/quic-go/frames"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("StreamFrameQueue", func() {
	var prioFrame1, prioFrame2 *frames.StreamFrame
	var frame1, frame2 *frames.StreamFrame
	var queue StreamFrameQueue

	BeforeEach(func() {
		queue = StreamFrameQueue{}
		prioFrame1 = &frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}
		prioFrame2 = &frames.StreamFrame{
			StreamID: 6,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}
		frame1 = &frames.StreamFrame{
			StreamID: 10,
			Data:     []byte{0xCA, 0xFE},
		}
		frame2 = &frames.StreamFrame{
			StreamID: 11,
			Data:     []byte{0xDE, 0xAD, 0xBE, 0xEF},
		}
	})

	Context("Queue Length", func() {
		It("returns the correct length for an empty queue", func() {
			Expect(queue.Len()).To(BeZero())
		})

		It("returns the correct lengths for a queue", func() {
			queue.Push(prioFrame1, true)
			Expect(queue.Len()).To(Equal(1))
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			Expect(queue.Len()).To(Equal(3))
		})

		It("returns the correct length when popping", func() {
			queue.Push(prioFrame1, true)
			queue.Push(prioFrame2, true)
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			Expect(queue.Len()).To(Equal(4))
			queue.Pop()
			Expect(queue.Len()).To(Equal(3))
			queue.Pop()
			queue.Pop()
			queue.Pop()
			Expect(queue.Len()).To(Equal(0))
		})
	})

	Context("Popping", func() {
		It("returns nil when popping an empty queue", func() {
			Expect(queue.Pop()).To(BeNil())
		})

		It("deletes elements once they are popped", func() {
			queue.Push(frame1, false)
			Expect(queue.Pop()).To(Equal(frame1))
			Expect(queue.Pop()).To(BeNil())
		})

		It("returns normal frames if no prio frames are available", func() {
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			Expect(queue.Pop()).To(Equal(frame1))
			Expect(queue.Pop()).To(Equal(frame2))
		})

		It("returns prio frames first", func() {
			queue.Push(prioFrame1, true)
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			queue.Push(prioFrame2, true)
			Expect(queue.Pop()).To(Equal(prioFrame1))
			Expect(queue.Pop()).To(Equal(prioFrame2))
			Expect(queue.Pop()).To(Equal(frame1))
		})
	})

	Context("Front", func() {
		It("returns nil for an empty queue", func() {
			Expect(queue.Front()).To(BeNil())
		})

		It("returns normal frames if no prio frames are available", func() {
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			Expect(queue.Front()).To(Equal(frame1))
			Expect(queue.Len()).To(Equal(2))
			Expect(queue.Front()).To(Equal(frame1))
			Expect(queue.Len()).To(Equal(2))
		})

		It("returns prio frames first", func() {
			queue.Push(prioFrame1, true)
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			queue.Push(prioFrame2, true)
			Expect(queue.Front()).To(Equal(prioFrame1))
			Expect(queue.Len()).To(Equal(4))
		})
	})
})
