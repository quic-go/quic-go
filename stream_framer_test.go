package quic

import (
	"bytes"
	"sync"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream Framer", func() {
	var (
		retransmittedFrame1, retransmittedFrame2 *frames.StreamFrame
		framer                                   *streamFramer
		streamsMap                               map[protocol.StreamID]*stream
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
		streamsMap = map[protocol.StreamID]*stream{
			1: nil, 2: nil, 3: nil, 4: nil, // we have to be able to deal with nil frames
			10: stream1,
			11: stream2,
		}

		fcm = newMockFlowControlHandler()
		fcm.sendWindowSizes[stream1.streamID] = protocol.MaxByteCount
		fcm.sendWindowSizes[stream2.streamID] = protocol.MaxByteCount
		fcm.sendWindowSizes[retransmittedFrame1.StreamID] = protocol.MaxByteCount
		fcm.sendWindowSizes[retransmittedFrame2.StreamID] = protocol.MaxByteCount
		framer = newStreamFramer(&streamsMap, &sync.RWMutex{}, fcm)
	})

	It("sets the DataLenPresent for dequeued retransmitted frames", func() {
		framer.AddFrameForRetransmission(retransmittedFrame1)
		f, err := framer.PopStreamFrame(protocol.MaxByteCount)
		Expect(err).NotTo(HaveOccurred())
		Expect(f.DataLenPresent).To(BeTrue())
	})

	It("sets the DataLenPresent for dequeued normal frames", func() {
		stream1.dataForWriting = []byte("foobar")
		f, err := framer.PopStreamFrame(protocol.MaxByteCount)
		Expect(err).NotTo(HaveOccurred())
		Expect(f.DataLenPresent).To(BeTrue())
	})

	Context("HasData", func() {
		It("has no data initially", func() {
			Expect(framer.HasData()).To(BeFalse())
		})

		It("has data with retransmitted frames", func() {
			framer.AddFrameForRetransmission(retransmittedFrame1)
			Expect(framer.HasData()).To(BeTrue())
		})

		It("has data with normal frames", func() {
			stream1.dataForWriting = []byte("foobar")
			Expect(framer.HasData()).To(BeTrue())
		})

		It("has data with FIN frames", func() {
			stream1.closed = 1
			Expect(framer.HasData()).To(BeTrue())
		})

	})

	Context("Framer estimated data length", func() {
		It("returns the correct length for an empty framer", func() {
			Expect(framer.EstimatedDataLen()).To(BeZero())
		})

		It("returns the correct byte length", func() {
			framer.AddFrameForRetransmission(retransmittedFrame1)
			Expect(framer.EstimatedDataLen()).To(Equal(protocol.ByteCount(2)))
			stream1.dataForWriting = []byte("foobar")
			Expect(framer.EstimatedDataLen()).To(Equal(protocol.ByteCount(2 + 6)))
		})

		It("returns the correct byte length when popping", func() {
			framer.AddFrameForRetransmission(retransmittedFrame1)
			stream1.dataForWriting = []byte("foobar")
			Expect(framer.EstimatedDataLen()).To(Equal(protocol.ByteCount(2 + 6)))
			framer.PopStreamFrame(1000)
			Expect(framer.EstimatedDataLen()).To(Equal(protocol.ByteCount(6)))
			framer.PopStreamFrame(1000)
			Expect(framer.EstimatedDataLen()).To(BeZero())
		})

		It("includes estimated FIN frames", func() {
			stream1.closed = 1
			// estimate for an average frame containing only a FIN bit
			Expect(framer.EstimatedDataLen()).To(Equal(protocol.ByteCount(5)))
		})

		It("caps the length", func() {
			stream1.dataForWriting = bytes.Repeat([]byte{'a'}, int(protocol.MaxPacketSize)+10)
			Expect(framer.EstimatedDataLen()).To(Equal(protocol.MaxFrameAndPublicHeaderSize))
		})
	})

	Context("Popping", func() {
		It("returns nil when popping an empty framer", func() {
			Expect(framer.PopStreamFrame(1000)).To(BeNil())
		})

		It("pops frames for retransmission", func() {
			framer.AddFrameForRetransmission(retransmittedFrame1)
			framer.AddFrameForRetransmission(retransmittedFrame2)
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(retransmittedFrame1))
			frame, err = framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(retransmittedFrame2))
			frame, err = framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeNil())
		})

		It("returns normal frames", func() {
			stream1.dataForWriting = []byte("foobar")
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(stream1.streamID))
			Expect(frame.Data).To(Equal([]byte("foobar")))
			frame, err = framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeNil())
		})

		It("returns multiple normal frames", func() {
			stream1.dataForWriting = []byte("foobar")
			stream2.dataForWriting = []byte("foobaz")
			frame1, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			frame2, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			// Swap if we dequeued in other order
			if frame1.StreamID != stream1.streamID {
				frame1, frame2 = frame2, frame1
			}
			Expect(frame1.StreamID).To(Equal(stream1.streamID))
			Expect(frame1.Data).To(Equal([]byte("foobar")))
			Expect(frame2.StreamID).To(Equal(stream2.streamID))
			Expect(frame2.Data).To(Equal([]byte("foobaz")))
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeNil())
		})

		It("returns retransmission frames before normal frames", func() {
			framer.AddFrameForRetransmission(retransmittedFrame1)
			stream1.dataForWriting = []byte("foobar")
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(retransmittedFrame1))
			frame, err = framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(stream1.streamID))
			frame, err = framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeNil())
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
				frame, err := framer.PopStreamFrame(6)
				Expect(err).ToNot(HaveOccurred())
				minLength, _ := frame.MinLength(0)
				Expect(minLength + frame.DataLen()).To(Equal(protocol.ByteCount(6)))
				Expect(framer.retransmissionQueue[0].Data).To(HaveLen(int(origlen - frame.DataLen())))
				Expect(framer.retransmissionQueue[0].Offset).To(Equal(frame.DataLen()))
			})

			It("only removes a frame from the framer after returning all split parts", func() {
				framer.AddFrameForRetransmission(retransmittedFrame2)
				frame, err := framer.PopStreamFrame(6)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).ToNot(BeNil())
				Expect(framer.HasData()).To(BeTrue())
				frame, err = framer.PopStreamFrame(100)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).ToNot(BeNil())
				Expect(framer.HasData()).To(BeFalse())
			})

			It("gets the whole data of a frame if it was split", func() {
				origdata := []byte("foobar")
				stream1.dataForWriting = origdata
				frame, err := framer.PopStreamFrame(7)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.Data).To(Equal([]byte("foo")))
				var b bytes.Buffer
				frame.Write(&b, 0)
				Expect(b.Len()).To(Equal(7))
				frame, err = framer.PopStreamFrame(1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.Data).To(Equal([]byte("bar")))
			})

			It("correctly calculates the byte length when returning a split frame", func() {
				framer.AddFrameForRetransmission(retransmittedFrame1)
				framer.AddFrameForRetransmission(retransmittedFrame2)
				startByteLength := framer.EstimatedDataLen()
				frame, err := framer.PopStreamFrame(6)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(retransmittedFrame1.StreamID)) // make sure the right frame was popped
				Expect(framer.EstimatedDataLen()).To(Equal(startByteLength - frame.DataLen()))
			})
		})

		Context("sending FINs", func() {
			It("sends FINs when streams are closed", func() {
				stream1.writeOffset = 42
				stream1.closed = 1
				frame, err := framer.PopStreamFrame(1000)
				Expect(err).NotTo(HaveOccurred())
				Expect(frame.StreamID).To(Equal(stream1.streamID))
				Expect(frame.Offset).To(Equal(stream1.writeOffset))
				Expect(frame.FinBit).To(BeTrue())
				Expect(frame.Data).To(BeEmpty())
			})
		})
	})

	Context("flow control", func() {
		It("tells the FlowControlManager how many bytes it sent", func() {
			stream1.dataForWriting = []byte("foobar")
			_, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.bytesSent).To(Equal(protocol.ByteCount(6)))
		})

		It("does not count retransmitted frames as sent bytes", func() {
			framer.AddFrameForRetransmission(retransmittedFrame1)
			_, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.bytesSent).To(BeZero())
		})

		It("returns the whole frame if it fits", func() {
			stream1.writeOffset = 10
			stream1.dataForWriting = []byte("foobar")
			fcm.sendWindowSizes[stream1.streamID] = 10 + 6
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.DataLen()).To(Equal(protocol.ByteCount(6)))
		})

		It("returns a smaller frame if the whole frame doesn't fit", func() {
			stream1.dataForWriting = []byte("foobar")
			fcm.sendWindowSizes[stream1.streamID] = 3
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Data).To(Equal([]byte("foo")))
		})

		It("returns a smaller frame if the whole frame doesn't fit in the stream flow control window, for non-zero StreamFrame offset", func() {
			stream1.writeOffset = 1
			stream1.dataForWriting = []byte("foobar")
			fcm.sendWindowSizes[stream1.StreamID()] = 4
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Data).To(Equal([]byte("foo")))
		})

		It("returns a smaller frame if the whole frame doesn't fit in the connection flow control window", func() {
			stream1.dataForWriting = []byte("foobar")
			fcm.streamsContributing = []protocol.StreamID{stream1.StreamID()}
			fcm.remainingConnectionWindowSize = 3
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Data).To(Equal([]byte("foo")))
		})

		It("ignores the connection flow control window for non-contributing streams", func() {
			stream1.dataForWriting = []byte("foobar")
			fcm.remainingConnectionWindowSize = 0
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Data).To(Equal([]byte("foobar")))
		})

		It("respects the connection flow control window for contributing streams", func() {
			stream1.dataForWriting = []byte("foobar")
			fcm.remainingConnectionWindowSize = 0
			fcm.streamsContributing = []protocol.StreamID{stream1.StreamID()}
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeNil())
		})

		It("selects a stream that is not flow control blocked", func() {
			fcm.sendWindowSizes[stream1.StreamID()] = 0
			stream1.dataForWriting = []byte("foobar")
			stream2.dataForWriting = []byte("foobaz")
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(stream2.StreamID()))
			Expect(frame.Data).To(Equal([]byte("foobaz")))
		})

		It("chooses a non-contributing stream if the connection is flow control blocked", func() {
			stream1.dataForWriting = []byte("foobar")
			stream2.dataForWriting = []byte("foobaz")
			fcm.streamsContributing = []protocol.StreamID{stream1.StreamID()}
			fcm.remainingConnectionWindowSize = 0
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(stream2.StreamID()))
		})

		It("returns nil if every stream is individually flow control blocked", func() {
			fcm.sendWindowSizes[stream1.StreamID()] = 0
			fcm.sendWindowSizes[stream2.StreamID()] = 0
			stream1.dataForWriting = []byte("foobar")
			stream2.dataForWriting = []byte("foobaz")
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeNil())
		})

		It("returns nil if every stream is connection flow control blocked", func() {
			fcm.remainingConnectionWindowSize = 0
			stream1.dataForWriting = []byte("foobar")
			stream2.dataForWriting = []byte("foobaz")
			fcm.streamsContributing = []protocol.StreamID{stream1.StreamID(), stream2.StreamID()}
			frame, err := framer.PopStreamFrame(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeNil())
		})
	})
})

// Old stream tests

// PContext("Blocked streams", func() {
// 	It("notifies the session when a stream is flow control blocked", func() {
// 		updated, err := str.flowControlManager.UpdateWindow(str.streamID, 1337)
// 		Expect(err).ToNot(HaveOccurred())
// 		Expect(updated).To(BeTrue())
// 		str.flowControlManager.AddBytesSent(str.streamID, 1337)
// 		str.maybeTriggerBlocked()
// 		Expect(handler.receivedBlockedCalled).To(BeTrue())
// 		Expect(handler.receivedBlockedForStream).To(Equal(str.streamID))
// 	})
//
// 	It("notifies the session as soon as a stream is reaching the end of the window", func() {
// 		updated, err := str.flowControlManager.UpdateWindow(str.streamID, 4)
// 		Expect(err).ToNot(HaveOccurred())
// 		Expect(updated).To(BeTrue())
// 		str.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD})
// 		Expect(handler.receivedBlockedCalled).To(BeTrue())
// 		Expect(handler.receivedBlockedForStream).To(Equal(str.streamID))
// 	})
//
// 	It("notifies the session as soon as a stream is flow control blocked", func() {
// 		updated, err := str.flowControlManager.UpdateWindow(str.streamID, 2)
// 		Expect(err).ToNot(HaveOccurred())
// 		Expect(updated).To(BeTrue())
// 		go func() {
// 			str.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD})
// 		}()
// 		time.Sleep(time.Millisecond)
// 		Expect(handler.receivedBlockedCalled).To(BeTrue())
// 		Expect(handler.receivedBlockedForStream).To(Equal(str.streamID))
// 	})
// })
