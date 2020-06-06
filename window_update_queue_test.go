package quic

import (
	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Window Update Queue", func() {
	var (
		q            *windowUpdateQueue
		streamGetter *MockStreamGetter
		connFC       *mocks.MockConnectionFlowController
		queuedFrames []ackhandler.Frame
	)

	BeforeEach(func() {
		streamGetter = NewMockStreamGetter(mockCtrl)
		connFC = mocks.NewMockConnectionFlowController(mockCtrl)
		queuedFrames = queuedFrames[:0]
		q = newWindowUpdateQueue(streamGetter, connFC, func(f ackhandler.Frame) {
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
		Expect(queuedFrames).To(HaveLen(2))
		frames := []wire.Frame{queuedFrames[0].Frame, queuedFrames[1].Frame}
		Expect(frames).To(ContainElement(&wire.MaxStreamDataFrame{StreamID: 1, ByteOffset: 10}))
		Expect(frames).To(ContainElement(&wire.MaxStreamDataFrame{StreamID: 3, ByteOffset: 30}))
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
		Expect(queuedFrames).To(HaveLen(1))
		Expect(queuedFrames[0].Frame).To(Equal(&wire.MaxDataFrame{ByteOffset: 0x1337}))
	})

	It("deduplicates", func() {
		stream10 := NewMockStreamI(mockCtrl)
		stream10.EXPECT().getWindowUpdate().Return(protocol.ByteCount(200))
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(10)).Return(stream10, nil)
		q.AddStream(10)
		q.AddStream(10)
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(1))
		Expect(queuedFrames[0].Frame).To(Equal(&wire.MaxStreamDataFrame{StreamID: 10, ByteOffset: 200}))
	})

	It("queues a retransmission for a lost MAX_DATA frame", func() {
		connFC.EXPECT().GetWindowUpdate().Return(protocol.ByteCount(0x42))
		q.AddConnection()
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(1))
		f := queuedFrames[0]
		Expect(f.Frame).To(Equal(&wire.MaxDataFrame{ByteOffset: 0x42}))

		queuedFrames = nil
		// make sure there's no MAX_DATA frame queued
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
		// now lose the frame
		f.OnLost(f.Frame)
		connFC.EXPECT().GetWindowUpdate().Return(protocol.ByteCount(0x1337))
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(1))
		f = queuedFrames[0]
		Expect(f.Frame).To(Equal(&wire.MaxDataFrame{ByteOffset: 0x1337}))
	})

	It("queues a retransmission for a lost MAX_STREAM_DATA frame", func() {
		stream12 := NewMockStreamI(mockCtrl)
		stream12.EXPECT().getWindowUpdate().Return(protocol.ByteCount(1000))
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(12)).Return(stream12, nil)
		q.AddStream(12)
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(1))
		f := queuedFrames[0]
		Expect(f.Frame).To(Equal(&wire.MaxStreamDataFrame{StreamID: 12, ByteOffset: 1000}))

		queuedFrames = nil
		// make sure there's no MAX_STREAM_DATA frame queued
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
		// now lose the frame
		f.OnLost(f.Frame)
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(12)).Return(stream12, nil)
		stream12.EXPECT().getWindowUpdate().Return(protocol.ByteCount(2000))
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(1))
		f = queuedFrames[0]
		Expect(f.Frame).To(Equal(&wire.MaxStreamDataFrame{StreamID: 12, ByteOffset: 2000}))
	})

	It("queues a retransmissions for lost MAX_STREAM_DATA frames, for mulitple streams", func() {
		stream11 := NewMockStreamI(mockCtrl)
		stream11.EXPECT().getWindowUpdate().Return(protocol.ByteCount(1000))
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(11)).Return(stream11, nil)
		q.AddStream(11)
		stream12 := NewMockStreamI(mockCtrl)
		stream12.EXPECT().getWindowUpdate().Return(protocol.ByteCount(1000))
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(12)).Return(stream12, nil)
		q.AddStream(12)
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(2))
		queuedFrames[0].OnLost(queuedFrames[0].Frame)
		queuedFrames[1].OnLost(queuedFrames[1].Frame)

		queuedFrames = nil
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(11)).Return(stream11, nil)
		stream11.EXPECT().getWindowUpdate().Return(protocol.ByteCount(2000))
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(12)).Return(stream12, nil)
		stream12.EXPECT().getWindowUpdate().Return(protocol.ByteCount(3000))
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(2))
		frames := []wire.Frame{queuedFrames[0].Frame, queuedFrames[1].Frame}
		Expect(frames).To(ContainElement(&wire.MaxStreamDataFrame{StreamID: 11, ByteOffset: 2000}))
		Expect(frames).To(ContainElement(&wire.MaxStreamDataFrame{StreamID: 12, ByteOffset: 3000}))
	})

	It("doesn't queue a retransmission for a lost MAX_STREAM_DATA frame, if the stream is already closed", func() {
		stream12 := NewMockStreamI(mockCtrl)
		stream12.EXPECT().getWindowUpdate().Return(protocol.ByteCount(1000))
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(12)).Return(stream12, nil)
		q.AddStream(12)
		q.QueueAll()
		Expect(queuedFrames).To(HaveLen(1))
		f := queuedFrames[0]
		Expect(f.Frame).To(Equal(&wire.MaxStreamDataFrame{StreamID: 12, ByteOffset: 1000}))

		queuedFrames = nil
		// make sure there's no MAX_STREAM_DATA frame queued
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
		// now lose the frame
		f.OnLost(f.Frame)
		streamGetter.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(12)).Return(nil, nil)
		q.QueueAll()
		Expect(queuedFrames).To(BeEmpty())
	})

})
