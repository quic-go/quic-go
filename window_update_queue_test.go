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
		streamGetter *MockStreamGetter
		connFC       *mocks.MockConnectionFlowController
		queuedFrames []wire.Frame
	)

	BeforeEach(func() {
		streamGetter = NewMockStreamGetter(mockCtrl)
		connFC = mocks.NewMockConnectionFlowController(mockCtrl)
		queuedFrames = queuedFrames[:0]
		q = newWindowUpdateQueue(streamGetter, connFC, func(f wire.Frame) {
			queuedFrames = append(queuedFrames, f)
		})
	})

	It("adds stream offsets and gets MAX_STREAM_DATA frames", func() {
		stream1 := NewMockStreamI(mockCtrl)
		stream1.EXPECT().getWindowUpdate().Return(protocol.ByteCount(10))
		stream3 := NewMockStreamI(mockCtrl)
		stream3.EXPECT().getWindowUpdate().Return(protocol.ByteCount(30))
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(3)).Return(stream3, nil)
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(1)).Return(stream1, nil)
		q.AddStream(3)
		q.AddStream(1)
		q.QueueAll()
		Expect(queuedFrames).To(ContainElement(&wire.MaxStreamDataFrame{StreamID: 1, MaximumStreamData: 10}))
		Expect(queuedFrames).To(ContainElement(&wire.MaxStreamDataFrame{StreamID: 3, MaximumStreamData: 30}))
	})

	It("deletes the entry after getting the MAX_STREAM_DATA frame", func() {
		stream10 := NewMockStreamI(mockCtrl)
		stream10.EXPECT().getWindowUpdate().Return(protocol.ByteCount(100))
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(10)).Return(stream10, nil)
		q.AddStream(10)
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(1))
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(1))
	})

	It("doesn't queue a MAX_STREAM_DATA for a closed stream", func() {
		q.AddStream(12)
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(12)).Return(nil, nil)
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
	})

	It("removes closed streams from the queue", func() {
		q.AddStream(12)
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(12)).Return(nil, nil)
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
		// don't EXPECT any further calls to GetOrOpenReceiveStream
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
	})

	It("doesn't queue a MAX_STREAM_DATA if the flow controller returns an offset of 0", func() {
		stream5 := NewMockStreamI(mockCtrl)
		stream5.EXPECT().getWindowUpdate().Return(protocol.ByteCount(0))
		q.AddStream(5)
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(5)).Return(stream5, nil)
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
	})

	It("removes streams for which the flow controller returns an offset of 0 from the queue", func() {
		stream5 := NewMockStreamI(mockCtrl)
		stream5.EXPECT().getWindowUpdate().Return(protocol.ByteCount(0))
		q.AddStream(5)
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(5)).Return(stream5, nil)
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
		// don't EXPECT any further calls to GetOrOpenReveiveStream and to getWindowUpdate
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
	})

	It("queues MAX_DATA frames", func() {
		connFC.EXPECT().GetWindowUpdate().Return(protocol.ByteCount(0x1337))
		q.AddConnection()
		q.QueueAll()
		Expect(queuedFrames).To(Equal([]wire.Frame{
			&wire.MaxDataFrame{MaximumData: 0x1337},
		}))
	})

	It("deduplicates", func() {
		stream10 := NewMockStreamI(mockCtrl)
		stream10.EXPECT().getWindowUpdate().Return(protocol.ByteCount(200))
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(10)).Return(stream10, nil)
		q.AddStream(10)
		q.AddStream(10)
		q.QueueAll()
		Expect(queuedFrames).To(Equal([]wire.Frame{
			&wire.MaxStreamDataFrame{StreamID: 10, MaximumStreamData: 200},
		}))
	})
})
