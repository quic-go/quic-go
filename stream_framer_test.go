package quic

import (
	"bytes"

	"github.com/golang/mock/gomock"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream Framer", func() {
	const (
		id1 = protocol.StreamID(10)
		id2 = protocol.StreamID(11)
	)

	var (
		retransmittedFrame1, retransmittedFrame2 *wire.StreamFrame
		framer                                   *streamFramer
		cryptoStream                             *MockCryptoStream
		stream1, stream2                         *MockSendStreamI
		streamGetter                             *MockStreamGetter
	)

	BeforeEach(func() {
		streamGetter = NewMockStreamGetter(mockCtrl)
		retransmittedFrame1 = &wire.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}
		retransmittedFrame2 = &wire.StreamFrame{
			StreamID: 6,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}

		stream1 = NewMockSendStreamI(mockCtrl)
		stream1.EXPECT().StreamID().Return(protocol.StreamID(5)).AnyTimes()
		stream2 = NewMockSendStreamI(mockCtrl)
		stream2.EXPECT().StreamID().Return(protocol.StreamID(6)).AnyTimes()
		cryptoStream = NewMockCryptoStream(mockCtrl)
		framer = newStreamFramer(cryptoStream, streamGetter, versionGQUICFrames)
	})

	It("says if it has retransmissions", func() {
		Expect(framer.HasFramesForRetransmission()).To(BeFalse())
		framer.AddFrameForRetransmission(retransmittedFrame1)
		Expect(framer.HasFramesForRetransmission()).To(BeTrue())
	})

	It("sets the DataLenPresent for dequeued retransmitted frames", func() {
		framer.AddFrameForRetransmission(retransmittedFrame1)
		fs := framer.PopStreamFrames(protocol.MaxByteCount)
		Expect(fs).To(HaveLen(1))
		Expect(fs[0].DataLenPresent).To(BeTrue())
	})

	Context("handling the crypto stream", func() {
		It("says if it has crypto stream data", func() {
			Expect(framer.HasCryptoStreamData()).To(BeFalse())
			framer.AddActiveStream(framer.version.CryptoStreamID())
			Expect(framer.HasCryptoStreamData()).To(BeTrue())
		})

		It("says that it doesn't have crypto stream data after popping all data", func() {
			streamID := framer.version.CryptoStreamID()
			f := &wire.StreamFrame{
				StreamID: streamID,
				Data:     []byte("foobar"),
			}
			cryptoStream.EXPECT().popStreamFrame(protocol.ByteCount(1000)).Return(f, false)
			framer.AddActiveStream(streamID)
			Expect(framer.PopCryptoStreamFrame(1000)).To(Equal(f))
			Expect(framer.HasCryptoStreamData()).To(BeFalse())
		})

		It("says that it has more crypto stream data if not all data was popped", func() {
			streamID := framer.version.CryptoStreamID()
			f := &wire.StreamFrame{
				StreamID: streamID,
				Data:     []byte("foobar"),
			}
			cryptoStream.EXPECT().popStreamFrame(protocol.ByteCount(1000)).Return(f, true)
			framer.AddActiveStream(streamID)
			Expect(framer.PopCryptoStreamFrame(1000)).To(Equal(f))
			Expect(framer.HasCryptoStreamData()).To(BeTrue())
		})
	})

	Context("Popping", func() {
		It("returns nil when popping an empty framer", func() {
			Expect(framer.PopStreamFrames(1000)).To(BeEmpty())
		})

		It("pops frames for retransmission", func() {
			framer.AddFrameForRetransmission(retransmittedFrame1)
			framer.AddFrameForRetransmission(retransmittedFrame2)
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(Equal([]*wire.StreamFrame{retransmittedFrame1, retransmittedFrame2}))
			// make sure the frames are actually removed, and not returned a second time
			Expect(framer.PopStreamFrames(1000)).To(BeEmpty())
		})

		It("doesn't pop frames for retransmission, if the size would be smaller than the minimum STREAM frame size", func() {
			framer.AddFrameForRetransmission(&wire.StreamFrame{
				StreamID: id1,
				Data:     bytes.Repeat([]byte{'a'}, int(protocol.MinStreamFrameSize)),
			})
			fs := framer.PopStreamFrames(protocol.MinStreamFrameSize - 1)
			Expect(fs).To(BeEmpty())
		})

		It("pops frames for retransmission, even if the remaining space in the packet is too small, if the frame doesn't need to be split", func() {
			framer.AddFrameForRetransmission(retransmittedFrame1)
			fs := framer.PopStreamFrames(protocol.MinStreamFrameSize - 1)
			Expect(fs).To(Equal([]*wire.StreamFrame{retransmittedFrame1}))
		})

		It("pops frames for retransmission, if the remaining size is the miniumum STREAM frame size", func() {
			framer.AddFrameForRetransmission(retransmittedFrame1)
			fs := framer.PopStreamFrames(protocol.MinStreamFrameSize)
			Expect(fs).To(Equal([]*wire.StreamFrame{retransmittedFrame1}))
		})

		It("returns normal frames", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			f := &wire.StreamFrame{
				StreamID: id1,
				Data:     []byte("foobar"),
				Offset:   42,
			}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f, false)
			framer.AddActiveStream(id1)
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(Equal([]*wire.StreamFrame{f}))
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
			Expect(framer.PopStreamFrames(1000)).To(Equal([]*wire.StreamFrame{f}))
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
			Expect(framer.PopStreamFrames(1000)).To(Equal([]*wire.StreamFrame{f}))
		})

		It("pops from a stream multiple times, if it has enough data", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil).Times(2)
			f1 := &wire.StreamFrame{StreamID: id1, Data: []byte("foobar")}
			f2 := &wire.StreamFrame{StreamID: id1, Data: []byte("foobaz")}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f1, true)
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f2, false)
			framer.AddActiveStream(id1) // only add it once
			Expect(framer.PopStreamFrames(protocol.MinStreamFrameSize)).To(Equal([]*wire.StreamFrame{f1}))
			Expect(framer.PopStreamFrames(protocol.MinStreamFrameSize)).To(Equal([]*wire.StreamFrame{f2}))
			// no further calls to popStreamFrame, after popStreamFrame said there's no more data
			Expect(framer.PopStreamFrames(protocol.MinStreamFrameSize)).To(BeNil())
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
			Expect(framer.PopStreamFrames(protocol.MinStreamFrameSize)).To(Equal([]*wire.StreamFrame{f11})) // first a frame from stream 1
			Expect(framer.PopStreamFrames(protocol.MinStreamFrameSize)).To(Equal([]*wire.StreamFrame{f2}))  // then a frame from stream 2
			Expect(framer.PopStreamFrames(protocol.MinStreamFrameSize)).To(Equal([]*wire.StreamFrame{f12})) // then another frame from stream 1
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
			Expect(framer.PopStreamFrames(1000)).To(Equal([]*wire.StreamFrame{f1, f2}))
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
			Expect(framer.PopStreamFrames(1000)).To(Equal([]*wire.StreamFrame{f2, f1}))
		})

		It("only asks a stream for data once, even if it was reported active multiple times", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			f := &wire.StreamFrame{Data: []byte("foobar")}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f, false) // only one call to this function
			framer.AddActiveStream(id1)
			framer.AddActiveStream(id1)
			Expect(framer.PopStreamFrames(1000)).To(HaveLen(1))
		})

		It("returns retransmission frames before normal frames", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			framer.AddActiveStream(id1)
			f1 := &wire.StreamFrame{Data: []byte("foobar")}
			stream1.EXPECT().popStreamFrame(gomock.Any()).Return(f1, false)
			framer.AddFrameForRetransmission(retransmittedFrame1)
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(Equal([]*wire.StreamFrame{retransmittedFrame1, f1}))
		})

		It("does not pop empty frames", func() {
			fs := framer.PopStreamFrames(500)
			Expect(fs).To(BeEmpty())
		})

		It("pops frames that have the minimum size", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			stream1.EXPECT().popStreamFrame(protocol.MinStreamFrameSize).Return(&wire.StreamFrame{Data: []byte("foobar")}, false)
			framer.AddActiveStream(id1)
			framer.PopStreamFrames(protocol.MinStreamFrameSize)
		})

		It("does not pop frames smaller than the mimimum size", func() {
			// don't expect a call to PopStreamFrame()
			framer.PopStreamFrames(protocol.MinStreamFrameSize - 1)
		})

		It("stops iterating when the remaining size is smaller than the minimum STREAM frame size", func() {
			streamGetter.EXPECT().GetOrOpenSendStream(id1).Return(stream1, nil)
			// pop a frame such that the remaining size is one byte less than the minimum STREAM frame size
			f := &wire.StreamFrame{
				StreamID: id1,
				Data:     bytes.Repeat([]byte("f"), int(500-protocol.MinStreamFrameSize)),
			}
			stream1.EXPECT().popStreamFrame(protocol.ByteCount(500)).Return(f, false)
			framer.AddActiveStream(id1)
			fs := framer.PopStreamFrames(500)
			Expect(fs).To(Equal([]*wire.StreamFrame{f}))
		})

		Context("splitting of frames", func() {
			It("splits off nothing", func() {
				f := &wire.StreamFrame{
					StreamID: 1,
					Data:     []byte("bar"),
					Offset:   3,
				}
				Expect(maybeSplitOffFrame(f, 1000)).To(BeNil())
				Expect(f.Offset).To(Equal(protocol.ByteCount(3)))
				Expect(f.Data).To(Equal([]byte("bar")))
			})

			It("splits off initial frame", func() {
				f := &wire.StreamFrame{
					StreamID:       1,
					Data:           []byte("foobar"),
					DataLenPresent: true,
					Offset:         3,
					FinBit:         true,
				}
				previous := maybeSplitOffFrame(f, 3)
				Expect(previous).ToNot(BeNil())
				Expect(previous.StreamID).To(Equal(protocol.StreamID(1)))
				Expect(previous.Data).To(Equal([]byte("foo")))
				Expect(previous.DataLenPresent).To(BeTrue())
				Expect(previous.Offset).To(Equal(protocol.ByteCount(3)))
				Expect(previous.FinBit).To(BeFalse())
				Expect(f.StreamID).To(Equal(protocol.StreamID(1)))
				Expect(f.Data).To(Equal([]byte("bar")))
				Expect(f.DataLenPresent).To(BeTrue())
				Expect(f.Offset).To(Equal(protocol.ByteCount(6)))
				Expect(f.FinBit).To(BeTrue())
			})

			It("splits a frame", func() {
				frame := &wire.StreamFrame{Data: bytes.Repeat([]byte{0}, 600)}
				framer.AddFrameForRetransmission(frame)
				fs := framer.PopStreamFrames(500)
				Expect(fs).To(HaveLen(1))
				minLength := fs[0].MinLength(framer.version)
				Expect(minLength + fs[0].DataLen()).To(Equal(protocol.ByteCount(500)))
				Expect(framer.retransmissionQueue[0].Data).To(HaveLen(int(600 - fs[0].DataLen())))
				Expect(framer.retransmissionQueue[0].Offset).To(Equal(fs[0].DataLen()))
			})

			It("only removes a frame from the framer after returning all split parts", func() {
				frameHeaderLen := protocol.ByteCount(4)
				frame := &wire.StreamFrame{Data: bytes.Repeat([]byte{0}, int(501-frameHeaderLen))}
				framer.AddFrameForRetransmission(frame)
				fs := framer.PopStreamFrames(500)
				Expect(fs).To(HaveLen(1))
				Expect(framer.retransmissionQueue).ToNot(BeEmpty())
				fs = framer.PopStreamFrames(500)
				Expect(fs).To(HaveLen(1))
				Expect(fs[0].DataLen()).To(BeEquivalentTo(1))
				Expect(framer.retransmissionQueue).To(BeEmpty())
			})
		})
	})
})
