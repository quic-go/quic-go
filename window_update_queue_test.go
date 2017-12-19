package quic

import (
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Window Update Queue", func() {
	var (
		q            *windowUpdateQueue
		queuedFrames []wire.Frame
	)

	BeforeEach(func() {
		queuedFrames = queuedFrames[:0]
		q = newWindowUpdateQueue(func(f wire.Frame) {
			queuedFrames = append(queuedFrames, f)
		})
	})

	It("adds stream offsets and gets MAX_STREAM_DATA frames", func() {
		q.Add(1, 10)
		q.Add(2, 20)
		q.Add(3, 30)
		q.QueueAll()
		Expect(queuedFrames).To(ContainElement(&wire.MaxStreamDataFrame{StreamID: 1, ByteOffset: 10}))
		Expect(queuedFrames).To(ContainElement(&wire.MaxStreamDataFrame{StreamID: 2, ByteOffset: 20}))
		Expect(queuedFrames).To(ContainElement(&wire.MaxStreamDataFrame{StreamID: 3, ByteOffset: 30}))
	})

	It("deletes the entry after getting the MAX_STREAM_DATA frame", func() {
		q.Add(10, 100)
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(1))
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(1))
	})

	It("replaces old entries", func() {
		q.Add(10, 100)
		q.Add(10, 200)
		q.QueueAll()
		Expect(queuedFrames).To(Equal([]wire.Frame{
			&wire.MaxStreamDataFrame{StreamID: 10, ByteOffset: 200},
		}))
	})
})
