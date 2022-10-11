package quic

import (
	"bytes"
	"math/rand"

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo/v2"
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
			mdf := &wire.MaxDataFrame{MaximumData: 0x42}
			msf := &wire.MaxStreamsFrame{MaxStreamNum: 0x1337}
			framer.QueueControlFrame(mdf)
			framer.QueueControlFrame(msf)
			frames, length := framer.AppendControlFrames(nil, 1000)
			Expect(frames).To(HaveLen(2))
			fs := []wire.Frame{frames[0].Frame, frames[1].Frame}
			Expect(fs).To(ContainElement(mdf))
			Expect(fs).To(ContainElement(msf))
			Expect(length).To(Equal(mdf.Length(version) + msf.Length(version)))
		})

		It("says if it has data", func() {
			Expect(framer.HasData()).To(BeFalse())
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			framer.QueueControlFrame(f)
			Expect(framer.HasData()).To(BeTrue())
			frames, _ := framer.AppendControlFrames(nil, 1000)
			Expect(frames).To(HaveLen(1))
			Expect(framer.HasData()).To(BeFalse())
		})

		It("appends to the slice given", func() {
			ping := &wire.PingFrame{}
			mdf := &wire.MaxDataFrame{MaximumData: 0x42}
			framer.QueueControlFrame(mdf)
			frames, length := framer.AppendControlFrames([]ackhandler.Frame{{Frame: ping}}, 1000)
			Expect(frames).To(HaveLen(2))
			Expect(frames[0].Frame).To(Equal(ping))
			Expect(frames[1].Frame).To(Equal(mdf))
			Expect(length).To(Equal(mdf.Length(version)))
		})

		It("adds the right number of frames", func() {
			maxSize := protocol.ByteCount(1000)
			bf := &wire.DataBlockedFrame{MaximumData: 0x1337}
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

		It("drops *_BLOCKED frames when 0-RTT is rejected", func() {
			ping := &wire.PingFrame{}
			ncid := &wire.NewConnectionIDFrame{
				SequenceNumber: 10,
				ConnectionID:   protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			}
			frames := []wire.Frame{
				&wire.DataBlockedFrame{MaximumData: 1337},
				&wire.StreamDataBlockedFrame{StreamID: 42, MaximumStreamData: 1337},
				&wire.StreamsBlockedFrame{StreamLimit: 13},
				ping,
				ncid,
			}
			rand.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })
			for _, f := range frames {
				framer.QueueControlFrame(f)
			}
			Expect(framer.Handle0RTTRejection()).To(Succeed())
			fs, length := framer.AppendControlFrames(nil, protocol.MaxByteCount)
			Expect(fs).To(HaveLen(2))
			Expect(length).To(Equal(ping.Length(version) + ncid.Length(version)))
		})
	})

	Context("popping STREAM frames", func() {
		It("returns nil when popping an empty framer", func() {
			Expect(framer.AppendStreamFrames(nil, 1000)).To(BeEmpty())
		})

		It("returns STREAM frames", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			f := &wire.StreamFrame{
				StreamID:       id1,
				Data:           []byte("foobar"),
				Offset:         42,
				DataLenPresent: true,
			}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f}, false)
			framer.AddActiveStream(id1)
			fs, length := framer.AppendStreamFrames(nil, 1000)
			Expect(fs).To(HaveLen(1))
			Expect(fs[0].Frame.(*wire.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(length).To(Equal(f.Length(version)))
		})

		It("says if it has data", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil).Times(2)
			Expect(framer.HasData()).To(BeFalse())
			framer.AddActiveStream(id1)
			Expect(framer.HasData()).To(BeTrue())
			f1 := &wire.StreamFrame{StreamID: id1, Data: []byte("foo")}
			f2 := &wire.StreamFrame{StreamID: id1, Data: []byte("bar")}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f1}, true)
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f2}, false)
			frames, _ := framer.AppendStreamFrames(nil, protocol.MaxByteCount)
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].Frame).To(Equal(f1))
			Expect(framer.HasData()).To(BeTrue())
			frames, _ = framer.AppendStreamFrames(nil, protocol.MaxByteCount)
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].Frame).To(Equal(f2))
			Expect(framer.HasData()).To(BeFalse())
		})

		It("appends to a frame slice", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			f := &wire.StreamFrame{
				StreamID:       id1,
				Data:           []byte("foobar"),
				DataLenPresent: true,
			}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f}, false)
			framer.AddActiveStream(id1)
			mdf := &wire.MaxDataFrame{MaximumData: 1337}
			frames := []ackhandler.Frame{{Frame: mdf}}
			fs, length := framer.AppendStreamFrames(frames, 1000)
			Expect(fs).To(HaveLen(2))
			Expect(fs[0].Frame).To(Equal(mdf))
			Expect(fs[1].Frame.(*wire.StreamFrame).Data).To(Equal([]byte("foobar")))
			Expect(fs[1].Frame.(*wire.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(length).To(Equal(f.Length(version)))
		})

		It("skips a stream that was reported active, but was completed shortly after", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(nil, nil)
			streamGetter.EXPECT().GetOrOpenSendStream(id2).Return(stream2, nil)
			f := &wire.StreamFrame{
				StreamID:       id2,
				Data:           []byte("foobar"),
				DataLenPresent: true,
			}
			stream2.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f}, false)
			framer.AddActiveStream(id1)
			framer.AddActiveStream(id2)
			frames, _ := framer.AppendStreamFrames(nil, 1000)
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].Frame).To(Equal(f))
		})

		It("skips a stream that was reported active, but doesn't have any data", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			streamGetter.EXPECT().GetOrOpenSendStream(id2).Return(stream2, nil)
			f := &wire.StreamFrame{
				StreamID:       id2,
				Data:           []byte("foobar"),
				DataLenPresent: true,
			}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(nil, false)
			stream2.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f}, false)
			framer.AddActiveStream(id1)
			framer.AddActiveStream(id2)
			frames, _ := framer.AppendStreamFrames(nil, 1000)
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].Frame).To(Equal(f))
		})

		It("pops from a stream multiple times, if it has enough data", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil).Times(2)
			f1 := &wire.StreamFrame{StreamID: id1, Data: []byte("foobar")}
			f2 := &wire.StreamFrame{StreamID: id1, Data: []byte("foobaz")}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f1}, true)
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f2}, false)
			framer.AddActiveStream(id1) // only add it once
			frames, _ := framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize)
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].Frame).To(Equal(f1))
			frames, _ = framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize)
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].Frame).To(Equal(f2))
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
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f11}, true)
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f12}, false)
			stream2.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f2}, false)
			framer.AddActiveStream(id1) // only add it once
			framer.AddActiveStream(id2)
			// first a frame from stream 1
			frames, _ := framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize)
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].Frame).To(Equal(f11))
			// then a frame from stream 2
			frames, _ = framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize)
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].Frame).To(Equal(f2))
			// then another frame from stream 1
			frames, _ = framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize)
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].Frame).To(Equal(f12))
		})

		It("only dequeues data from each stream once per packet", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			streamGetter.EXPECT().GetOrOpenSendStream(id2).Return(stream2, nil)
			f1 := &wire.StreamFrame{StreamID: id1, Data: []byte("foobar")}
			f2 := &wire.StreamFrame{StreamID: id2, Data: []byte("raboof")}
			// both streams have more data, and will be re-queued
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f1}, true)
			stream2.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f2}, true)
			framer.AddActiveStream(id1)
			framer.AddActiveStream(id2)
			frames, length := framer.AppendStreamFrames(nil, 1000)
			Expect(frames).To(HaveLen(2))
			Expect(frames[0].Frame).To(Equal(f1))
			Expect(frames[1].Frame).To(Equal(f2))
			Expect(length).To(Equal(f1.Length(version) + f2.Length(version)))
		})

		It("returns multiple normal frames in the order they were reported active", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			streamGetter.EXPECT().GetOrOpenSendStream(id2).Return(stream2, nil)
			f1 := &wire.StreamFrame{Data: []byte("foobar")}
			f2 := &wire.StreamFrame{Data: []byte("foobaz")}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f1}, false)
			stream2.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f2}, false)
			framer.AddActiveStream(id2)
			framer.AddActiveStream(id1)
			frames, _ := framer.AppendStreamFrames(nil, 1000)
			Expect(frames).To(HaveLen(2))
			Expect(frames[0].Frame).To(Equal(f2))
			Expect(frames[1].Frame).To(Equal(f1))
		})

		It("only asks a stream for data once, even if it was reported active multiple times", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			f := &wire.StreamFrame{Data: []byte("foobar")}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f}, false) // only one call to this function
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
				stream1.EXPECT().popStreamFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) (*ackhandler.Frame, bool) {
					f := &wire.StreamFrame{
						StreamID:       id1,
						DataLenPresent: true,
					}
					f.Data = make([]byte, f.MaxDataLen(size, version))
					Expect(f.Length(version)).To(Equal(size))
					return &ackhandler.Frame{Frame: f}, false
				})
				framer.AddActiveStream(id1)
				frames, _ := framer.AppendStreamFrames(nil, i)
				Expect(frames).To(HaveLen(1))
				f := frames[0].Frame.(*wire.StreamFrame)
				Expect(f.DataLenPresent).To(BeFalse())
				Expect(f.Length(version)).To(Equal(i))
			}
		})

		It("pops multiple STREAM frames", func() {
			for i := 2 * protocol.MinStreamFrameSize; i < 2000; i++ {
				streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
				streamGetter.EXPECT().GetOrOpenSendStream(id2).Return(stream2, nil)
				stream1.EXPECT().popStreamFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) (*ackhandler.Frame, bool) {
					f := &wire.StreamFrame{
						StreamID:       id2,
						DataLenPresent: true,
					}
					f.Data = make([]byte, f.MaxDataLen(protocol.MinStreamFrameSize, version))
					return &ackhandler.Frame{Frame: f}, false
				})
				stream2.EXPECT().popStreamFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) (*ackhandler.Frame, bool) {
					f := &wire.StreamFrame{
						StreamID:       id2,
						DataLenPresent: true,
					}
					f.Data = make([]byte, f.MaxDataLen(size, version))
					Expect(f.Length(version)).To(Equal(size))
					return &ackhandler.Frame{Frame: f}, false
				})
				framer.AddActiveStream(id1)
				framer.AddActiveStream(id2)
				frames, _ := framer.AppendStreamFrames(nil, i)
				Expect(frames).To(HaveLen(2))
				f1 := frames[0].Frame.(*wire.StreamFrame)
				f2 := frames[1].Frame.(*wire.StreamFrame)
				Expect(f1.DataLenPresent).To(BeTrue())
				Expect(f2.DataLenPresent).To(BeFalse())
				Expect(f1.Length(version) + f2.Length(version)).To(Equal(i))
			}
		})

		It("pops frames that when asked for the the minimum STREAM frame size", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			f := &wire.StreamFrame{Data: []byte("foobar")}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f}, false)
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
				StreamID:       id1,
				Data:           bytes.Repeat([]byte("f"), int(500-protocol.MinStreamFrameSize)),
				DataLenPresent: true,
			}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(&ackhandler.Frame{Frame: f}, false)
			framer.AddActiveStream(id1)
			fs, length := framer.AppendStreamFrames(nil, 500)
			Expect(fs).To(HaveLen(1))
			Expect(fs[0].Frame).To(Equal(f))
			Expect(length).To(Equal(f.Length(version)))
		})

		It("drops all STREAM frames when 0-RTT is rejected", func() {
			framer.AddActiveStream(id1)
			Expect(framer.Handle0RTTRejection()).To(Succeed())
			fs, length := framer.AppendStreamFrames(nil, protocol.MaxByteCount)
			Expect(fs).To(BeEmpty())
			Expect(length).To(BeZero())
		})
	})
})
