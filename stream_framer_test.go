package quic

import (
	"bytes"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/mocks"

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
		streamsMap                               *streamsMap
		stream1, stream2                         *mocks.MockStreamI
		connFC                                   *mocks.MockConnectionFlowController
	)

	BeforeEach(func() {
		retransmittedFrame1 = &wire.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}
		retransmittedFrame2 = &wire.StreamFrame{
			StreamID: 6,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}

		stream1 = mocks.NewMockStreamI(mockCtrl)
		stream1.EXPECT().StreamID().Return(protocol.StreamID(5)).AnyTimes()
		stream2 = mocks.NewMockStreamI(mockCtrl)
		stream2.EXPECT().StreamID().Return(protocol.StreamID(6)).AnyTimes()

		streamsMap = newStreamsMap(nil, protocol.PerspectiveServer, versionGQUICFrames)
		streamsMap.putStream(stream1)
		streamsMap.putStream(stream2)

		connFC = mocks.NewMockConnectionFlowController(mockCtrl)
		framer = newStreamFramer(nil, streamsMap, connFC, versionGQUICFrames)
	})

	setNoData := func(str *mocks.MockStreamI) {
		str.EXPECT().HasDataForWriting().Return(false).AnyTimes()
		str.EXPECT().GetDataForWriting(gomock.Any()).Return(nil, false).AnyTimes()
		str.EXPECT().GetWriteOffset().AnyTimes()
	}

	It("says if it has retransmissions", func() {
		Expect(framer.HasFramesForRetransmission()).To(BeFalse())
		framer.AddFrameForRetransmission(retransmittedFrame1)
		Expect(framer.HasFramesForRetransmission()).To(BeTrue())
	})

	It("sets the DataLenPresent for dequeued retransmitted frames", func() {
		setNoData(stream1)
		setNoData(stream2)
		framer.AddFrameForRetransmission(retransmittedFrame1)
		fs := framer.PopStreamFrames(protocol.MaxByteCount)
		Expect(fs).To(HaveLen(1))
		Expect(fs[0].DataLenPresent).To(BeTrue())
	})

	It("sets the DataLenPresent for dequeued normal frames", func() {
		connFC.EXPECT().IsBlocked()
		setNoData(stream2)
		stream1.EXPECT().GetWriteOffset()
		stream1.EXPECT().HasDataForWriting().Return(true)
		stream1.EXPECT().GetDataForWriting(gomock.Any()).Return([]byte("foobar"), false)
		stream1.EXPECT().IsFlowControlBlocked()
		fs := framer.PopStreamFrames(protocol.MaxByteCount)
		Expect(fs).To(HaveLen(1))
		Expect(fs[0].DataLenPresent).To(BeTrue())
	})

	Context("Popping", func() {
		BeforeEach(func() {
			// nothing is blocked here
			connFC.EXPECT().IsBlocked().AnyTimes()
			stream1.EXPECT().IsFlowControlBlocked().Return(false).AnyTimes()
			stream2.EXPECT().IsFlowControlBlocked().Return(false).AnyTimes()
		})

		It("returns nil when popping an empty framer", func() {
			setNoData(stream1)
			setNoData(stream2)
			Expect(framer.PopStreamFrames(1000)).To(BeEmpty())
		})

		It("pops frames for retransmission", func() {
			setNoData(stream1)
			setNoData(stream2)
			framer.AddFrameForRetransmission(retransmittedFrame1)
			framer.AddFrameForRetransmission(retransmittedFrame2)
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(2))
			Expect(fs[0]).To(Equal(retransmittedFrame1))
			Expect(fs[1]).To(Equal(retransmittedFrame2))
			Expect(framer.PopStreamFrames(1000)).To(BeEmpty())
		})

		It("returns normal frames", func() {
			stream1.EXPECT().GetDataForWriting(gomock.Any()).Return([]byte("foobar"), false)
			stream1.EXPECT().HasDataForWriting().Return(true)
			stream1.EXPECT().GetWriteOffset()
			setNoData(stream2)
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(1))
			Expect(fs[0].StreamID).To(Equal(stream1.StreamID()))
			Expect(fs[0].Data).To(Equal([]byte("foobar")))
			Expect(fs[0].FinBit).To(BeFalse())
		})

		It("returns multiple normal frames", func() {
			stream1.EXPECT().GetDataForWriting(gomock.Any()).Return([]byte("foobar"), false)
			stream1.EXPECT().HasDataForWriting().Return(true)
			stream1.EXPECT().GetWriteOffset()
			stream2.EXPECT().GetDataForWriting(gomock.Any()).Return([]byte("foobaz"), false)
			stream2.EXPECT().HasDataForWriting().Return(true)
			stream2.EXPECT().GetWriteOffset()
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(2))
			// Swap if we dequeued in other order
			if fs[0].StreamID != stream1.StreamID() {
				fs[0], fs[1] = fs[1], fs[0]
			}
			Expect(fs[0].StreamID).To(Equal(stream1.StreamID()))
			Expect(fs[0].Data).To(Equal([]byte("foobar")))
			Expect(fs[1].StreamID).To(Equal(stream2.StreamID()))
			Expect(fs[1].Data).To(Equal([]byte("foobaz")))
		})

		It("returns retransmission frames before normal frames", func() {
			stream1.EXPECT().GetDataForWriting(gomock.Any()).Return([]byte("foobar"), false)
			stream1.EXPECT().HasDataForWriting().Return(true)
			stream1.EXPECT().GetWriteOffset()
			setNoData(stream2)
			framer.AddFrameForRetransmission(retransmittedFrame1)
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(2))
			Expect(fs[0]).To(Equal(retransmittedFrame1))
			Expect(fs[1].StreamID).To(Equal(stream1.StreamID()))
		})

		It("does not pop empty frames", func() {
			stream1.EXPECT().HasDataForWriting().Return(false)
			stream1.EXPECT().GetWriteOffset()
			setNoData(stream2)
			fs := framer.PopStreamFrames(5)
			Expect(fs).To(BeEmpty())
		})

		It("uses the round-robin scheduling", func() {
			streamFrameHeaderLen := protocol.ByteCount(4)
			stream1.EXPECT().GetDataForWriting(10-streamFrameHeaderLen).Return(bytes.Repeat([]byte("f"), int(10-streamFrameHeaderLen)), false)
			stream1.EXPECT().HasDataForWriting().Return(true)
			stream1.EXPECT().GetWriteOffset()
			stream2.EXPECT().GetDataForWriting(protocol.ByteCount(10-streamFrameHeaderLen)).Return(bytes.Repeat([]byte("e"), int(10-streamFrameHeaderLen)), false)
			stream2.EXPECT().HasDataForWriting().Return(true)
			stream2.EXPECT().GetWriteOffset()
			fs := framer.PopStreamFrames(10)
			Expect(fs).To(HaveLen(1))
			// it doesn't matter here if this data is from stream1 or from stream2...
			firstStreamID := fs[0].StreamID
			fs = framer.PopStreamFrames(10)
			Expect(fs).To(HaveLen(1))
			// ... but the data popped this time has to be from the other stream
			Expect(fs[0].StreamID).ToNot(Equal(firstStreamID))
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
				setNoData(stream1)
				setNoData(stream2)
				framer.AddFrameForRetransmission(retransmittedFrame2)
				origlen := retransmittedFrame2.DataLen()
				fs := framer.PopStreamFrames(6)
				Expect(fs).To(HaveLen(1))
				minLength, _ := fs[0].MinLength(framer.version)
				Expect(minLength + fs[0].DataLen()).To(Equal(protocol.ByteCount(6)))
				Expect(framer.retransmissionQueue[0].Data).To(HaveLen(int(origlen - fs[0].DataLen())))
				Expect(framer.retransmissionQueue[0].Offset).To(Equal(fs[0].DataLen()))
			})

			It("never returns an empty stream frame", func() {
				// this one frame will be split off from again and again in this test. Therefore, it has to be large enough (checked again at the end)
				origFrame := &wire.StreamFrame{
					StreamID: 5,
					Offset:   1,
					FinBit:   false,
					Data:     bytes.Repeat([]byte{'f'}, 30*30),
				}
				framer.AddFrameForRetransmission(origFrame)

				minFrameDataLen := protocol.MaxPacketSize

				for i := 0; i < 30; i++ {
					frames, currentLen := framer.maybePopFramesForRetransmission(protocol.ByteCount(i))
					if len(frames) == 0 {
						Expect(currentLen).To(BeZero())
					} else {
						Expect(frames).To(HaveLen(1))
						Expect(currentLen).ToNot(BeZero())
						dataLen := frames[0].DataLen()
						Expect(dataLen).ToNot(BeZero())
						if dataLen < minFrameDataLen {
							minFrameDataLen = dataLen
						}
					}
				}
				Expect(framer.retransmissionQueue).To(HaveLen(1)) // check that origFrame was large enough for this test and didn't get used up completely
				Expect(minFrameDataLen).To(Equal(protocol.ByteCount(1)))
			})

			It("only removes a frame from the framer after returning all split parts", func() {
				setNoData(stream1)
				setNoData(stream2)
				framer.AddFrameForRetransmission(retransmittedFrame2)
				fs := framer.PopStreamFrames(6)
				Expect(fs).To(HaveLen(1))
				Expect(framer.retransmissionQueue).ToNot(BeEmpty())
				fs = framer.PopStreamFrames(1000)
				Expect(fs).To(HaveLen(1))
				Expect(framer.retransmissionQueue).To(BeEmpty())
			})
		})

		Context("sending FINs", func() {
			It("sends FINs when streams are closed", func() {
				offset := protocol.ByteCount(42)
				stream1.EXPECT().HasDataForWriting().Return(true)
				stream1.EXPECT().GetDataForWriting(gomock.Any()).Return(nil, true)
				stream1.EXPECT().GetWriteOffset().Return(offset)
				setNoData(stream2)

				fs := framer.PopStreamFrames(1000)
				Expect(fs).To(HaveLen(1))
				Expect(fs[0].StreamID).To(Equal(stream1.StreamID()))
				Expect(fs[0].Offset).To(Equal(offset))
				Expect(fs[0].FinBit).To(BeTrue())
				Expect(fs[0].Data).To(BeEmpty())
			})

			It("bundles FINs with data", func() {
				offset := protocol.ByteCount(42)
				stream1.EXPECT().GetDataForWriting(gomock.Any()).Return([]byte("foobar"), true)
				stream1.EXPECT().HasDataForWriting().Return(true)
				stream1.EXPECT().GetWriteOffset().Return(offset)
				setNoData(stream2)

				fs := framer.PopStreamFrames(1000)
				Expect(fs).To(HaveLen(1))
				Expect(fs[0].StreamID).To(Equal(stream1.StreamID()))
				Expect(fs[0].Data).To(Equal([]byte("foobar")))
				Expect(fs[0].FinBit).To(BeTrue())
			})
		})
	})

	Context("BLOCKED frames", func() {
		It("Pop returns nil if no frame is queued", func() {
			Expect(framer.PopBlockedFrame()).To(BeNil())
		})

		It("queues and pops BLOCKED frames for individually blocked streams", func() {
			connFC.EXPECT().IsBlocked()
			stream1.EXPECT().GetDataForWriting(gomock.Any()).Return([]byte("foobar"), false)
			stream1.EXPECT().HasDataForWriting().Return(true)
			stream1.EXPECT().GetWriteOffset()
			stream1.EXPECT().IsFlowControlBlocked().Return(true)
			setNoData(stream2)
			frames := framer.PopStreamFrames(1000)
			Expect(frames).To(HaveLen(1))
			f := framer.PopBlockedFrame()
			Expect(f).To(BeAssignableToTypeOf(&wire.StreamBlockedFrame{}))
			bf := f.(*wire.StreamBlockedFrame)
			Expect(bf.StreamID).To(Equal(stream1.StreamID()))
			Expect(framer.PopBlockedFrame()).To(BeNil())
		})

		It("does not queue a stream-level BLOCKED frame after sending the FinBit frame", func() {
			connFC.EXPECT().IsBlocked()
			stream1.EXPECT().GetDataForWriting(gomock.Any()).Return([]byte("foo"), true)
			stream1.EXPECT().HasDataForWriting().Return(true)
			stream1.EXPECT().GetWriteOffset()
			setNoData(stream2)
			frames := framer.PopStreamFrames(1000)
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].FinBit).To(BeTrue())
			Expect(frames[0].DataLen()).To(Equal(protocol.ByteCount(3)))
			blockedFrame := framer.PopBlockedFrame()
			Expect(blockedFrame).To(BeNil())
		})

		It("queues and pops BLOCKED frames for connection blocked streams", func() {
			connFC.EXPECT().IsBlocked().Return(true)
			stream1.EXPECT().GetDataForWriting(gomock.Any()).Return([]byte("foo"), false)
			stream1.EXPECT().HasDataForWriting().Return(true)
			stream1.EXPECT().GetWriteOffset()
			stream1.EXPECT().IsFlowControlBlocked().Return(false)
			setNoData(stream2)
			framer.PopStreamFrames(1000)
			f := framer.PopBlockedFrame()
			Expect(f).To(BeAssignableToTypeOf(&wire.BlockedFrame{}))
			Expect(framer.PopBlockedFrame()).To(BeNil())
		})
	})
})
