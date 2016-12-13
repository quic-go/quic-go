package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream Framer", func() {
	var (
		retransmittedFrame1, retransmittedFrame2 *frames.StreamFrame
		framer                                   *streamFramer
		streamsMap                               *streamsMap
		stream1, stream2                         *stream
		fcm                                      *mockFlowControlHandler
	)

	BeforeEach(func() {
		retransmittedFrame1 = &frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}
		retransmittedFrame2 = &frames.StreamFrame{
			StreamID: 6,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}

		stream1 = &stream{streamID: 10}
		stream2 = &stream{streamID: 11}

		streamsMap = newStreamsMap(nil, protocol.PerspectiveServer, &mockConnectionParametersManager{})
		streamsMap.putStream(stream1)
		streamsMap.putStream(stream2)

		fcm = newMockFlowControlHandler()
		fcm.sendWindowSizes[stream1.streamID] = protocol.MaxByteCount
		fcm.sendWindowSizes[stream2.streamID] = protocol.MaxByteCount
		fcm.sendWindowSizes[retransmittedFrame1.StreamID] = protocol.MaxByteCount
		fcm.sendWindowSizes[retransmittedFrame2.StreamID] = protocol.MaxByteCount
		framer = newStreamFramer(streamsMap, fcm)
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

	It("sets the DataLenPresent for dequeued normal frames", func() {
		stream1.dataForWriting = []byte("foobar")
		fs := framer.PopStreamFrames(protocol.MaxByteCount)
		Expect(fs).To(HaveLen(1))
		Expect(fs[0].DataLenPresent).To(BeTrue())
	})

	Context("Popping", func() {
		It("returns nil when popping an empty framer", func() {
			Expect(framer.PopStreamFrames(1000)).To(BeEmpty())
		})

		It("pops frames for retransmission", func() {
			framer.AddFrameForRetransmission(retransmittedFrame1)
			framer.AddFrameForRetransmission(retransmittedFrame2)
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(2))
			Expect(fs[0]).To(Equal(retransmittedFrame1))
			Expect(fs[1]).To(Equal(retransmittedFrame2))
			Expect(framer.PopStreamFrames(1000)).To(BeEmpty())
		})

		It("returns normal frames", func() {
			stream1.dataForWriting = []byte("foobar")
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(1))
			Expect(fs[0].StreamID).To(Equal(stream1.streamID))
			Expect(fs[0].Data).To(Equal([]byte("foobar")))
			Expect(framer.PopStreamFrames(1000)).To(BeEmpty())
		})

		It("returns multiple normal frames", func() {
			stream1.dataForWriting = []byte("foobar")
			stream2.dataForWriting = []byte("foobaz")
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(2))
			// Swap if we dequeued in other order
			if fs[0].StreamID != stream1.streamID {
				fs[0], fs[1] = fs[1], fs[0]
			}
			Expect(fs[0].StreamID).To(Equal(stream1.streamID))
			Expect(fs[0].Data).To(Equal([]byte("foobar")))
			Expect(fs[1].StreamID).To(Equal(stream2.streamID))
			Expect(fs[1].Data).To(Equal([]byte("foobaz")))
			Expect(framer.PopStreamFrames(1000)).To(BeEmpty())
		})

		It("returns retransmission frames before normal frames", func() {
			framer.AddFrameForRetransmission(retransmittedFrame1)
			stream1.dataForWriting = []byte("foobar")
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(2))
			Expect(fs[0]).To(Equal(retransmittedFrame1))
			Expect(fs[1].StreamID).To(Equal(stream1.streamID))
			Expect(framer.PopStreamFrames(1000)).To(BeEmpty())
		})

		It("does not pop empty frames", func() {
			stream1.dataForWriting = []byte("foobar")
			fs := framer.PopStreamFrames(4)
			Expect(fs).To(HaveLen(0))
			fs = framer.PopStreamFrames(5)
			Expect(fs).To(HaveLen(1))
			Expect(fs[0].Data).ToNot(BeEmpty())
			Expect(fs[0].FinBit).To(BeFalse())
		})

		It("uses the round-robin scheduling", func() {
			stream1.dataForWriting = bytes.Repeat([]byte("f"), 100)
			stream2.dataForWriting = bytes.Repeat([]byte("e"), 100)
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
				f := &frames.StreamFrame{
					StreamID: 1,
					Data:     []byte("bar"),
					Offset:   3,
				}
				Expect(maybeSplitOffFrame(f, 1000)).To(BeNil())
				Expect(f.Offset).To(Equal(protocol.ByteCount(3)))
				Expect(f.Data).To(Equal([]byte("bar")))
			})

			It("splits off initial frame", func() {
				f := &frames.StreamFrame{
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
				framer.AddFrameForRetransmission(retransmittedFrame2)
				origlen := retransmittedFrame2.DataLen()
				fs := framer.PopStreamFrames(6)
				Expect(fs).To(HaveLen(1))
				minLength, _ := fs[0].MinLength(0)
				Expect(minLength + fs[0].DataLen()).To(Equal(protocol.ByteCount(6)))
				Expect(framer.retransmissionQueue[0].Data).To(HaveLen(int(origlen - fs[0].DataLen())))
				Expect(framer.retransmissionQueue[0].Offset).To(Equal(fs[0].DataLen()))
			})

			It("never returns an empty stream frame", func() {
				// this one frame will be split off from again and again in this test. Therefore, it has to be large enough (checked again at the end)
				origFrame := &frames.StreamFrame{
					StreamID: 5,
					Offset:   1,
					FinBit:   false,
					Data:     bytes.Repeat([]byte{'f'}, 30*30),
				}
				framer.AddFrameForRetransmission(origFrame)

				minFrameDataLen := protocol.MaxFrameAndPublicHeaderSize

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
				framer.AddFrameForRetransmission(retransmittedFrame2)
				fs := framer.PopStreamFrames(6)
				Expect(fs).To(HaveLen(1))
				Expect(framer.retransmissionQueue).ToNot(BeEmpty())
				fs = framer.PopStreamFrames(1000)
				Expect(fs).To(HaveLen(1))
				Expect(framer.retransmissionQueue).To(BeEmpty())
			})

			It("gets the whole data of a frame if it was split", func() {
				origdata := []byte("foobar")
				stream1.dataForWriting = origdata
				fs := framer.PopStreamFrames(7)
				Expect(fs).To(HaveLen(1))
				Expect(fs[0].Data).To(Equal([]byte("foo")))
				var b bytes.Buffer
				fs[0].Write(&b, 0)
				Expect(b.Len()).To(Equal(7))
				fs = framer.PopStreamFrames(1000)
				Expect(fs).To(HaveLen(1))
				Expect(fs[0].Data).To(Equal([]byte("bar")))
			})
		})

		Context("sending FINs", func() {
			It("sends FINs when streams are closed", func() {
				stream1.writeOffset = 42
				stream1.finishedWriting.Set(true)
				fs := framer.PopStreamFrames(1000)
				Expect(fs).To(HaveLen(1))
				Expect(fs[0].StreamID).To(Equal(stream1.streamID))
				Expect(fs[0].Offset).To(Equal(stream1.writeOffset))
				Expect(fs[0].FinBit).To(BeTrue())
				Expect(fs[0].Data).To(BeEmpty())
			})

			It("sends FINs when flow-control blocked", func() {
				stream1.writeOffset = 42
				stream1.finishedWriting.Set(true)
				fcm.sendWindowSizes[stream1.StreamID()] = 42
				fs := framer.PopStreamFrames(1000)
				Expect(fs).To(HaveLen(1))
				Expect(fs[0].StreamID).To(Equal(stream1.streamID))
				Expect(fs[0].Offset).To(Equal(stream1.writeOffset))
				Expect(fs[0].FinBit).To(BeTrue())
				Expect(fs[0].Data).To(BeEmpty())
			})

			It("bundles FINs with data", func() {
				stream1.dataForWriting = []byte("foobar")
				stream1.finishedWriting.Set(true)
				fs := framer.PopStreamFrames(1000)
				Expect(fs).To(HaveLen(1))
				Expect(fs[0].StreamID).To(Equal(stream1.streamID))
				Expect(fs[0].Data).To(Equal([]byte("foobar")))
				Expect(fs[0].FinBit).To(BeTrue())
			})
		})
	})

	Context("flow control", func() {
		It("tells the FlowControlManager how many bytes it sent", func() {
			stream1.dataForWriting = []byte("foobar")
			framer.PopStreamFrames(1000)
			Expect(fcm.bytesSent).To(Equal(protocol.ByteCount(6)))
		})

		It("does not count retransmitted frames as sent bytes", func() {
			framer.AddFrameForRetransmission(retransmittedFrame1)
			framer.PopStreamFrames(1000)
			Expect(fcm.bytesSent).To(BeZero())
		})

		It("returns the whole frame if it fits", func() {
			stream1.writeOffset = 10
			stream1.dataForWriting = []byte("foobar")
			fcm.sendWindowSizes[stream1.streamID] = 10 + 6
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(1))
			Expect(fs[0].DataLen()).To(Equal(protocol.ByteCount(6)))
		})

		It("returns a smaller frame if the whole frame doesn't fit", func() {
			stream1.dataForWriting = []byte("foobar")
			fcm.sendWindowSizes[stream1.streamID] = 3
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(1))
			Expect(fs[0].Data).To(Equal([]byte("foo")))
		})

		It("returns a smaller frame if the whole frame doesn't fit in the stream flow control window, for non-zero StreamFrame offset", func() {
			stream1.writeOffset = 1
			stream1.dataForWriting = []byte("foobar")
			fcm.sendWindowSizes[stream1.StreamID()] = 3
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(1))
			Expect(fs[0].Data).To(Equal([]byte("foo")))
		})

		It("returns a smaller frame if the whole frame doesn't fit in the connection flow control window", func() {
			stream1.dataForWriting = []byte("foobar")
			fcm.streamsContributing = []protocol.StreamID{stream1.StreamID()}
			fcm.remainingConnectionWindowSize = 3
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(1))
			Expect(fs[0].Data).To(Equal([]byte("foo")))
		})

		It("ignores the connection flow control window for non-contributing streams", func() {
			stream1.dataForWriting = []byte("foobar")
			fcm.remainingConnectionWindowSize = 0
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(1))
			Expect(fs[0].Data).To(Equal([]byte("foobar")))
		})

		It("respects the connection flow control window for contributing streams", func() {
			stream1.dataForWriting = []byte("foobar")
			fcm.remainingConnectionWindowSize = 0
			fcm.streamsContributing = []protocol.StreamID{stream1.StreamID()}
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(BeEmpty())
		})

		It("selects a stream that is not flow control blocked", func() {
			fcm.sendWindowSizes[stream1.StreamID()] = 0
			stream1.dataForWriting = []byte("foobar")
			stream2.dataForWriting = []byte("foobaz")
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(1))
			Expect(fs[0].StreamID).To(Equal(stream2.StreamID()))
			Expect(fs[0].Data).To(Equal([]byte("foobaz")))
		})

		It("chooses a non-contributing stream if the connection is flow control blocked", func() {
			stream1.dataForWriting = []byte("foobar")
			stream2.dataForWriting = []byte("foobaz")
			fcm.streamsContributing = []protocol.StreamID{stream1.StreamID()}
			fcm.remainingConnectionWindowSize = 0
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(HaveLen(1))
			Expect(fs[0].StreamID).To(Equal(stream2.StreamID()))
		})

		It("returns nil if every stream is individually flow control blocked", func() {
			fcm.sendWindowSizes[stream1.StreamID()] = 0
			fcm.sendWindowSizes[stream2.StreamID()] = 0
			stream1.dataForWriting = []byte("foobar")
			stream2.dataForWriting = []byte("foobaz")
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(BeEmpty())
		})

		It("returns nil if every stream is connection flow control blocked", func() {
			fcm.remainingConnectionWindowSize = 0
			stream1.dataForWriting = []byte("foobar")
			stream2.dataForWriting = []byte("foobaz")
			fcm.streamsContributing = []protocol.StreamID{stream1.StreamID(), stream2.StreamID()}
			fs := framer.PopStreamFrames(1000)
			Expect(fs).To(BeEmpty())
		})
	})

	Context("BLOCKED frames", func() {
		BeforeEach(func() {
			fcm.remainingConnectionWindowSize = protocol.MaxByteCount
		})

		It("Pop returns nil if no frame is queued", func() {
			Expect(framer.PopBlockedFrame()).To(BeNil())
		})

		It("queues and pops BLOCKED frames for individually blocked streams", func() {
			fcm.sendWindowSizes[stream1.StreamID()] = 3
			stream1.dataForWriting = []byte("foo")
			frames := framer.PopStreamFrames(1000)
			Expect(frames).To(HaveLen(1))
			blockedFrame := framer.PopBlockedFrame()
			Expect(blockedFrame).ToNot(BeNil())
			Expect(blockedFrame.StreamID).To(Equal(stream1.StreamID()))
			Expect(framer.PopBlockedFrame()).To(BeNil())
		})

		It("does not queue a stream-level BLOCKED frame after sending the FinBit frame", func() {
			fcm.sendWindowSizes[stream1.StreamID()] = 5000
			stream1.dataForWriting = []byte("foo")
			frames := framer.PopStreamFrames(1000)
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].FinBit).To(BeFalse())
			stream1.finishedWriting.Set(true)
			frames = framer.PopStreamFrames(1000)
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].FinBit).To(BeTrue())
			Expect(frames[0].DataLen()).To(BeZero())
			blockedFrame := framer.PopBlockedFrame()
			Expect(blockedFrame).To(BeNil())
		})

		It("queues and pops BLOCKED frames for connection blocked streams", func() {
			fcm.remainingConnectionWindowSize = 3
			fcm.streamsContributing = []protocol.StreamID{stream1.StreamID()}
			stream1.dataForWriting = []byte("foo")
			framer.PopStreamFrames(1000)
			blockedFrame := framer.PopBlockedFrame()
			Expect(blockedFrame).ToNot(BeNil())
			Expect(blockedFrame.StreamID).To(BeZero())
			Expect(framer.PopBlockedFrame()).To(BeNil())
		})

		It("does not queue BLOCKED frames for non-contributing streams", func() {
			fcm.remainingConnectionWindowSize = 3
			stream1.dataForWriting = []byte("foo")
			framer.PopStreamFrames(1000)
			Expect(framer.PopBlockedFrame()).To(BeNil())
		})

		It("does not queue BLOCKED frames twice", func() {
			fcm.sendWindowSizes[stream1.StreamID()] = 3
			stream1.dataForWriting = []byte("foobar")
			framer.PopStreamFrames(1000)
			blockedFrame := framer.PopBlockedFrame()
			Expect(blockedFrame).ToNot(BeNil())
			Expect(blockedFrame.StreamID).To(Equal(stream1.StreamID()))
			Expect(framer.PopBlockedFrame()).To(BeNil())
		})
	})
})
