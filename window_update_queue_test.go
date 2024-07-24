package quic

import (
	"github.com/quic-go/quic-go/internal/mocks"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Window Update Queue", func() {
	var (
		q            *windowUpdateQueue
		connFC       *mocks.MockConnectionFlowController
		queuedFrames []wire.Frame
	)

	BeforeEach(func() {
		connFC = mocks.NewMockConnectionFlowController(mockCtrl)
		queuedFrames = queuedFrames[:0]
		q = newWindowUpdateQueue(connFC, func(f wire.Frame) {
			queuedFrames = append(queuedFrames, f)
		})
	})

	It("adds stream offsets and gets MAX_STREAM_DATA frames", func() {
		connFC.EXPECT().GetWindowUpdate().Return(protocol.ByteCount(0)).AnyTimes()
		stream1 := NewMockStreamI(mockCtrl)
		stream1.EXPECT().getWindowUpdate().Return(protocol.ByteCount(10))
		stream3 := NewMockStreamI(mockCtrl)
		stream3.EXPECT().getWindowUpdate().Return(protocol.ByteCount(30))
		q.AddStream(3, stream3)
		q.AddStream(1, stream1)
		q.QueueAll()
		Expect(queuedFrames).To(ContainElement(&wire.MaxStreamDataFrame{StreamID: 1, MaximumStreamData: 10}))
		Expect(queuedFrames).To(ContainElement(&wire.MaxStreamDataFrame{StreamID: 3, MaximumStreamData: 30}))
	})

	It("deletes the entry after getting the MAX_STREAM_DATA frame", func() {
		connFC.EXPECT().GetWindowUpdate().Return(protocol.ByteCount(0)).AnyTimes()
		stream10 := NewMockStreamI(mockCtrl)
		stream10.EXPECT().getWindowUpdate().Return(protocol.ByteCount(100))
		q.AddStream(10, stream10)
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(1))
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(1))
	})

	It("doesn't queue a MAX_STREAM_DATA for a closed stream", func() {
		connFC.EXPECT().GetWindowUpdate().Return(protocol.ByteCount(0)).AnyTimes()
		stream12 := NewMockStreamI(mockCtrl)
		q.AddStream(12, stream12)
		q.RemoveStream(12)
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
	})

	It("removes closed streams from the queue", func() {
		connFC.EXPECT().GetWindowUpdate().Return(protocol.ByteCount(0)).AnyTimes()
		stream12 := NewMockStreamI(mockCtrl)
		q.AddStream(12, stream12)
		q.RemoveStream(12)
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
	})

	It("doesn't queue a MAX_STREAM_DATA if the flow controller returns an offset of 0", func() {
		connFC.EXPECT().GetWindowUpdate().Return(protocol.ByteCount(0))
		stream5 := NewMockStreamI(mockCtrl)
		stream5.EXPECT().getWindowUpdate().Return(protocol.ByteCount(0))
		q.AddStream(5, stream5)
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
	})

	It("removes streams for which the flow controller returns an offset of 0 from the queue", func() {
		connFC.EXPECT().GetWindowUpdate().Return(protocol.ByteCount(0)).AnyTimes()
		stream5 := NewMockStreamI(mockCtrl)
		stream5.EXPECT().getWindowUpdate().Return(protocol.ByteCount(0))
		q.AddStream(5, stream5)
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
		// don't EXPECT any further calls to GetOrOpenReveiveStream and to getWindowUpdate
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
	})

	It("queues MAX_DATA frames", func() {
		connFC.EXPECT().GetWindowUpdate().Return(protocol.ByteCount(0x1337))
		q.QueueAll()
		Expect(queuedFrames).To(Equal([]wire.Frame{&wire.MaxDataFrame{MaximumData: 0x1337}}))
	})

	It("deduplicates", func() {
		connFC.EXPECT().GetWindowUpdate().Return(protocol.ByteCount(0))
		stream10 := NewMockStreamI(mockCtrl)
		stream10.EXPECT().getWindowUpdate().Return(protocol.ByteCount(200))
		q.AddStream(10, stream10)
		q.AddStream(10, stream10)
		q.QueueAll()
		Expect(queuedFrames).To(Equal([]wire.Frame{&wire.MaxStreamDataFrame{StreamID: 10, MaximumStreamData: 200}}))
	})
})
