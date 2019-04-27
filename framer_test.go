package quic

import (
	"bytes"

	"github.com/golang/mock/gomock"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Framer", func() {
	const (
		id1 = protocol.StreamID(10)
		id2 = protocol.StreamID(11)
	)

	var (
		framer           framer
		stream1, stream2 *MockSendStreamI
		streamGetter     *MockStreamGetter
		version          protocol.VersionNumber
	)

	BeforeEach(func() {
		streamGetter = NewMockStreamGetter(mockCtrl)
		stream1 = NewMockSendStreamI(mockCtrl)
		stream1.EXPECT().StreamID().Return(protocol.StreamID(5)).AnyTimes()
		stream2 = NewMockSendStreamI(mockCtrl)
		stream2.EXPECT().StreamID().Return(protocol.StreamID(6)).AnyTimes()
		framer = newFramer(streamGetter, version)
	})

	Context("handling control frames", func() {
		It("adds control frames", func() {
			mdf := &wire.MaxDataFrame{ByteOffset: 0x42}
			msdf := &wire.MaxStreamDataFrame{ByteOffset: 0x1337}
			framer.QueueControlFrame(mdf)
			framer.QueueControlFrame(msdf)
			frames, length := framer.AppendControlFrames(nil, 1000)
			Expect(frames).To(ContainElement(mdf))
			Expect(frames).To(ContainElement(msdf))
			Expect(length).To(Equal(mdf.Length(version) + msdf.Length(version)))
		})

		It("appends to the slice given", func() {
			ack := &wire.AckFrame{}
			mdf := &wire.MaxDataFrame{ByteOffset: 0x42}
			framer.QueueControlFrame(mdf)
			frames, length := framer.AppendControlFrames([]wire.Frame{ack}, 1000)
			Expect(frames).To(Equal([]wire.Frame{ack, mdf}))
			Expect(length).To(Equal(mdf.Length(version)))
		})

		It("adds the right number of frames", func() {
			maxSize := protocol.ByteCount(1000)
			bf := &wire.DataBlockedFrame{DataLimit: 0x1337}
			bfLen := bf.Length(version)
			numFrames := int(maxSize / bfLen) // max number of frames that fit into maxSize
			for i := 0; i < numFrames+1; i++ {
				framer.QueueControlFrame(bf)
			}
			frames, length := framer.AppendControlFrames(nil, maxSize)
			Expect(frames).To(HaveLen(numFrames))
			Expect(length).To(BeNumerically(">", maxSize-bfLen))
			frames, length = framer.AppendControlFrames(nil, maxSize)
			Expect(frames).To(HaveLen(1))
			Expect(length).To(Equal(bfLen))
		})
	})

	Context("popping STREAM frames", func() {
		It("returns nil when popping an empty framer", func() {
			Expect(framer.AppendStreamFrames(nil, 1000)).To(BeEmpty())
		})

		It("returns STREAM frames", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			f := &wire.StreamFrame{
				StreamID: id1,
				Data:     []byte("foobar"),
				Offset:   42,
			}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f, false)
			framer.AddActiveStream(id1)
			fs, length := framer.AppendStreamFrames(nil, 1000)
			Expect(fs).To(Equal([]wire.Frame{f}))
			Expect(length).To(Equal(f.Length(version)))
		})

		It("appends to a frame slice", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			f := &wire.StreamFrame{
				StreamID: id1,
				Data:     []byte("foobar"),
			}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f, false)
			framer.AddActiveStream(id1)
			mdf := &wire.MaxDataFrame{ByteOffset: 1337}
			frames := []wire.Frame{mdf}
			fs, length := framer.AppendStreamFrames(frames, 1000)
			Expect(fs).To(Equal([]wire.Frame{mdf, f}))
			Expect(length).To(Equal(f.Length(version)))
		})

		It("skips a stream that was reported active, but was completed shortly after", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(nil, nil)
			streamGetter.EXPECT().GetOrOpenSendStream(id2).Return(stream2, nil)
			f := &wire.StreamFrame{
				StreamID: id2,
				Data:     []byte("foobar"),
			}
			stream2.EXPECT().popStreamFrame(gomock.Any()).Return(f, false)
			framer.AddActiveStream(id1)
			framer.AddActiveStream(id2)
			frames, _ := framer.AppendStreamFrames(nil, 1000)
			Expect(frames).To(Equal([]wire.Frame{f}))
		})

		It("skips a stream that was reported active, but doesn't have any data", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			streamGetter.EXPECT().GetOrOpenSendStream(id2).Return(stream2, nil)
			f := &wire.StreamFrame{
				StreamID: id2,
				Data:     []byte("foobar"),
			}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(nil, false)
			stream2.EXPECT().popStreamFrame(gomock.Any()).Return(f, false)
			framer.AddActiveStream(id1)
			framer.AddActiveStream(id2)
			frames, _ := framer.AppendStreamFrames(nil, 1000)
			Expect(frames).To(Equal([]wire.Frame{f}))
		})

		It("pops from a stream multiple times, if it has enough data", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil).Times(2)
			f1 := &wire.StreamFrame{StreamID: id1, Data: []byte("foobar")}
			f2 := &wire.StreamFrame{StreamID: id1, Data: []byte("foobaz")}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f1, true)
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f2, false)
			framer.AddActiveStream(id1) // only add it once
			frames, _ := framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize)
			Expect(frames).To(Equal([]wire.Frame{f1}))
			frames, _ = framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize)
			Expect(frames).To(Equal([]wire.Frame{f2}))
			// no further calls to popStreamFrame, after popStreamFrame said there's no more data
			frames, _ = framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize)
			Expect(frames).To(BeNil())
		})

		It("re-queues a stream at the end, if it has enough data", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil).Times(2)
			streamGetter.EXPECT().GetOrOpenSendStream(id2).Return(stream2, nil)
			f11 := &wire.StreamFrame{StreamID: id1, Data: []byte("foobar")}
			f12 := &wire.StreamFrame{StreamID: id1, Data: []byte("foobaz")}
			f2 := &wire.StreamFrame{StreamID: id2, Data: []byte("raboof")}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f11, true)
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f12, false)
			stream2.EXPECT().popStreamFrame(gomock.Any()).Return(f2, false)
			framer.AddActiveStream(id1) // only add it once
			framer.AddActiveStream(id2)
			// first a frame from stream 1
			frames, _ := framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize)
			Expect(frames).To(Equal([]wire.Frame{f11}))
			// then a frame from stream 2
			frames, _ = framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize)
			Expect(frames).To(Equal([]wire.Frame{f2}))
			// then another frame from stream 1
			frames, _ = framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize)
			Expect(frames).To(Equal([]wire.Frame{f12}))
		})

		It("only dequeues data from each stream once per packet", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			streamGetter.EXPECT().GetOrOpenSendStream(id2).Return(stream2, nil)
			f1 := &wire.StreamFrame{StreamID: id1, Data: []byte("foobar")}
			f2 := &wire.StreamFrame{StreamID: id2, Data: []byte("raboof")}
			// both streams have more data, and will be re-queued
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f1, true)
			stream2.EXPECT().popStreamFrame(gomock.Any()).Return(f2, true)
			framer.AddActiveStream(id1)
			framer.AddActiveStream(id2)
			frames, length := framer.AppendStreamFrames(nil, 1000)
			Expect(frames).To(Equal([]wire.Frame{f1, f2}))
			Expect(length).To(Equal(f1.Length(version) + f2.Length(version)))
		})

		It("returns multiple normal frames in the order they were reported active", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			streamGetter.EXPECT().GetOrOpenSendStream(id2).Return(stream2, nil)
			f1 := &wire.StreamFrame{Data: []byte("foobar")}
			f2 := &wire.StreamFrame{Data: []byte("foobaz")}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f1, false)
			stream2.EXPECT().popStreamFrame(gomock.Any()).Return(f2, false)
			framer.AddActiveStream(id2)
			framer.AddActiveStream(id1)
			frames, _ := framer.AppendStreamFrames(nil, 1000)
			Expect(frames).To(Equal([]wire.Frame{f2, f1}))
		})

		It("only asks a stream for data once, even if it was reported active multiple times", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			f := &wire.StreamFrame{Data: []byte("foobar")}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f, false) // only one call to this function
			framer.AddActiveStream(id1)
			framer.AddActiveStream(id1)
			frames, _ := framer.AppendStreamFrames(nil, 1000)
			Expect(frames).To(HaveLen(1))
		})

		It("does not pop empty frames", func() {
			fs, length := framer.AppendStreamFrames(nil, 500)
			Expect(fs).To(BeEmpty())
			Expect(length).To(BeZero())
		})

		It("pops maximum size STREAM frames", func() {
			for i := protocol.MinStreamFrameSize; i < 2000; i++ {
				streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
				stream1.EXPECT().popStreamFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) (*wire.StreamFrame, bool) {
					f := &wire.StreamFrame{
						StreamID:       id1,
						DataLenPresent: true,
					}
					f.Data = make([]byte, f.MaxDataLen(size, version))
					Expect(f.Length(version)).To(Equal(size))
					return f, false
				})
				framer.AddActiveStream(id1)
				frames, _ := framer.AppendStreamFrames(nil, i)
				Expect(frames).To(HaveLen(1))
				f := frames[0].(*wire.StreamFrame)
				Expect(f.DataLenPresent).To(BeFalse())
				Expect(f.Length(version)).To(Equal(i))
			}
		})

		It("pops multiple STREAM frames", func() {
			for i := 2 * protocol.MinStreamFrameSize; i < 2000; i++ {
				streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
				streamGetter.EXPECT().GetOrOpenSendStream(id2).Return(stream2, nil)
				stream1.EXPECT().popStreamFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) (*wire.StreamFrame, bool) {
					f := &wire.StreamFrame{
						StreamID:       id2,
						DataLenPresent: true,
					}
					f.Data = make([]byte, f.MaxDataLen(protocol.MinStreamFrameSize, version))
					return f, false
				})
				stream2.EXPECT().popStreamFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) (*wire.StreamFrame, bool) {
					f := &wire.StreamFrame{
						StreamID:       id2,
						DataLenPresent: true,
					}
					f.Data = make([]byte, f.MaxDataLen(size, version))
					Expect(f.Length(version)).To(Equal(size))
					return f, false
				})
				framer.AddActiveStream(id1)
				framer.AddActiveStream(id2)
				frames, _ := framer.AppendStreamFrames(nil, i)
				Expect(frames).To(HaveLen(2))
				f1 := frames[0].(*wire.StreamFrame)
				f2 := frames[1].(*wire.StreamFrame)
				Expect(f1.DataLenPresent).To(BeTrue())
				Expect(f2.DataLenPresent).To(BeFalse())
				Expect(f1.Length(version) + f2.Length(version)).To(Equal(i))
			}
		})

		It("pops frames that when asked for the the minimum STREAM frame size", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&wire.StreamFrame{Data: []byte("foobar")}, false)
			framer.AddActiveStream(id1)
			framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize)
		})

		It("does not pop frames smaller than the minimum size", func() {
			// don't expect a call to PopStreamFrame()
			framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize-1)
		})

		It("stops iterating when the remaining size is smaller than the minimum STREAM frame size", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			// pop a frame such that the remaining size is one byte less than the minimum STREAM frame size
			f := &wire.StreamFrame{
				StreamID: id1,
				Data:     bytes.Repeat([]byte("f"), int(500-protocol.MinStreamFrameSize)),
			}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f, false)
			framer.AddActiveStream(id1)
			fs, length := framer.AppendStreamFrames(nil, 500)
			Expect(fs).To(Equal([]wire.Frame{f}))
			Expect(length).To(Equal(f.Length(version)))
		})
	})
})
