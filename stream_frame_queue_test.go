package quic

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("streamFrameQueue", func() {
	var prioFrame1, prioFrame2 *frames.StreamFrame
	var frame1, frame2, frame3 *frames.StreamFrame
	var queue *streamFrameQueue

	BeforeEach(func() {
		queue = newStreamFrameQueue()
		prioFrame1 = &frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}
		prioFrame2 = &frames.StreamFrame{
			StreamID: 6,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}
		frame1 = &frames.StreamFrame{
			StreamID: 10,
			Data:     []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x13, 0x37},
		}
		frame2 = &frames.StreamFrame{
			StreamID: 11,
			Data:     []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x37},
		}
		frame3 = &frames.StreamFrame{
			StreamID: 11,
			Data:     []byte{0xBE, 0xEF},
		}
	})

	It("sets the DataLenPresent on all StreamFrames", func() {
		queue.Push(frame1, false)
		queue.Push(prioFrame1, true)
		Expect(queue.prioFrames[0].DataLenPresent).To(BeTrue())
		Expect(queue.frameMap[frame1.StreamID][0].DataLenPresent).To(BeTrue())
	})

	Context("Queue Length", func() {
		It("returns the correct length for an empty queue", func() {
			Expect(queue.Len()).To(BeZero())
		})

		It("returns the correct length for a queue", func() {
			queue.Push(prioFrame1, true)
			Expect(queue.Len()).To(Equal(1))
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			Expect(queue.Len()).To(Equal(3))
		})

		It("reduces the length when popping", func() {
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			Expect(queue.Len()).To(Equal(2))
			queue.Pop(1000)
			Expect(queue.Len()).To(Equal(1))
			queue.Pop(1000)
			Expect(queue.Len()).To(Equal(0))
		})

		It("reduces the length when deleting a stream for which a prio frame was queued", func() {
			queue.Push(prioFrame1, true)
			queue.Push(prioFrame2, true)
			Expect(queue.Len()).To(Equal(2))
			queue.RemoveStream(prioFrame1.StreamID)
			Expect(queue.Len()).To(Equal(1))
		})

		It("reduces the length when deleting a stream for which a normal frame was queued", func() {
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			Expect(queue.Len()).To(Equal(2))
			queue.RemoveStream(frame1.StreamID)
			Expect(queue.Len()).To(Equal(1))
		})
	})

	Context("Queue Byte Length", func() {
		It("returns the correct length for an empty queue", func() {
			Expect(queue.ByteLen()).To(BeZero())
		})

		It("returns the correct byte length for a queue", func() {
			queue.Push(prioFrame1, true)
			Expect(queue.ByteLen()).To(Equal(protocol.ByteCount(2)))
			queue.Push(frame2, false)
			Expect(queue.ByteLen()).To(Equal(prioFrame1.DataLen() + frame2.DataLen()))
		})

		It("returns the correct byte length when popping", func() {
			queue.Push(prioFrame1, true)
			queue.Push(frame1, false)
			Expect(queue.ByteLen()).To(Equal(prioFrame1.DataLen() + frame1.DataLen()))
			queue.Pop(1000)
			Expect(queue.ByteLen()).To(Equal(frame1.DataLen()))
			queue.Pop(1000)
			Expect(queue.ByteLen()).To(Equal(protocol.ByteCount(0)))
		})

		It("reduces the byte length when deleting a stream for which a prio frame was queued", func() {
			queue.Push(prioFrame1, true)
			queue.Push(prioFrame2, true)
			Expect(queue.ByteLen()).To(Equal(prioFrame1.DataLen() + prioFrame2.DataLen()))
			queue.RemoveStream(prioFrame1.StreamID)
			Expect(queue.ByteLen()).To(Equal(prioFrame2.DataLen()))
		})

		It("reduces the byte length when deleting a stream for which a normal frame was queued", func() {
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			Expect(queue.ByteLen()).To(Equal(frame1.DataLen() + frame2.DataLen()))
			queue.RemoveStream(frame1.StreamID)
			Expect(queue.ByteLen()).To(Equal(frame2.DataLen()))
		})
	})

	Context("Pushing", func() {
		It("adds the streams to the map", func() {
			queue.Push(frame1, false)
			Expect(queue.frameMap).To(HaveKey(frame1.StreamID))
			Expect(queue.frameMap[frame1.StreamID][0]).To(Equal(frame1))
		})

		It("only adds a StreamID once to the active stream list", func() {
			queue.Push(frame1, false)
			queue.Push(frame1, false)
			Expect(queue.frameMap).To(HaveKey(frame1.StreamID))
			Expect(queue.frameMap[frame1.StreamID]).To(HaveLen(2))
			Expect(queue.activeStreams).To(HaveLen(1))
			Expect(queue.activeStreams[0]).To(Equal(frame1.StreamID))
		})
	})

	Context("getNextStream", func() {
		It("returns 0 for an empty queue", func() {
			streamID, err := queue.getNextStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(streamID).To(BeZero())
		})

		It("does not change the byte length when using getNextStream()", func() {
			queue.Push(prioFrame1, true)
			queue.Push(frame1, false)
			length := prioFrame1.DataLen() + frame1.DataLen()
			Expect(queue.ByteLen()).To(Equal(length))
			_, err := queue.getNextStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(queue.ByteLen()).To(Equal(length))
		})

		It("does not change the length when using front()", func() {
			queue.Push(prioFrame1, true)
			queue.Push(frame1, false)
			Expect(queue.Len()).To(Equal(2))
			_, err := queue.getNextStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(queue.Len()).To(Equal(2))
		})

		It("returns normal frames if no prio frames are available", func() {
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			streamID, err := queue.getNextStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(streamID).To(Equal(frame1.StreamID))
		})

		It("gets the frame inserted at first at first", func() {
			queue.Push(frame2, false)
			queue.Push(frame1, false)
			streamID, err := queue.getNextStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(streamID).To(Equal(frame2.StreamID))
			streamID, err = queue.getNextStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(streamID).To(Equal(frame1.StreamID))
		})

		It("gets the next frame if a stream was deleted", func() {
			queue.Push(frame2, false)
			queue.Push(frame1, false)
			Expect(queue.activeStreams).To(ContainElement(frame1.StreamID))
			Expect(queue.activeStreams).To(ContainElement(frame2.StreamID))
			queue.RemoveStream(frame2.StreamID)
			Expect(queue.activeStreams).To(ContainElement(frame1.StreamID))
			Expect(queue.activeStreams).ToNot(ContainElement(frame2.StreamID))
			streamID, err := queue.getNextStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(streamID).To(Equal(frame1.StreamID))
		})
	})

	Context("Popping", func() {
		It("returns nil when popping an empty queue", func() {
			Expect(queue.Pop(1000)).To(BeNil())
		})

		It("deletes elements once they are popped", func() {
			queue.Push(frame1, false)
			frame, err := queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(frame1))
			frame, err = queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeNil())
		})

		It("returns normal frames if no prio frames are available", func() {
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			frame, err := queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(frame1))
			frame, err = queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(frame2))
		})

		It("returns prio frames first", func() {
			queue.Push(prioFrame1, true)
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			queue.Push(prioFrame2, true)
			frame, err := queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(prioFrame1))
			frame, err = queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(prioFrame2))
			frame, err = queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(frame1))
		})

		Context("scheduling", func() {
			It("goes around", func() {
				queue.Push(frame2, false) // StreamID: 11
				queue.Push(frame3, false) // StreamID: 11
				queue.Push(frame1, false) // StreamID: 10
				frame, err := queue.Pop(1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(frame2))
				frame, err = queue.Pop(1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(frame1))
				frame, err = queue.Pop(1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(frame3))
			})

			It("starts with the frame inserted first", func() {
				queue.Push(frame1, false) // StreamID: 10
				queue.Push(frame2, false) // StreamID: 11
				queue.Push(frame3, false) // StreamID: 11
				frame, err := queue.Pop(1000)
				Expect(frame).To(Equal(frame1))
				Expect(err).ToNot(HaveOccurred())
				frame, err = queue.Pop(1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(frame2))
				frame, err = queue.Pop(1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(frame3))
			})

			It("goes around, also when frame have to be split", func() {
				queue.Push(frame2, false) // StreamID: 11
				queue.Push(frame1, false) // StreamID: 10
				frame, err := queue.Pop(5)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(frame2.StreamID))
				frame, err = queue.Pop(1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(frame1))
				frame, err = queue.Pop(1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(frame2.StreamID))
			})
		})

		Context("splitting of frames", func() {
			It("splits off nothing", func() {
				f := &frames.StreamFrame{
					StreamID: 1,
					Data:     []byte("bar"),
					Offset:   3,
				}
				Expect(queue.maybeSplitOffFrame(f, 1000)).To(BeNil())
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
				minLength, _ := f.MinLength()
				previous := queue.maybeSplitOffFrame(f, minLength-1+3)
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
				queue.Push(frame1, false)
				origlen := frame1.DataLen()
				frame, err := queue.Pop(6)
				Expect(err).ToNot(HaveOccurred())
				minLength, _ := frame.MinLength()
				Expect(minLength - 1 + frame.DataLen()).To(Equal(protocol.ByteCount(6)))
				Expect(queue.frameMap[frame1.StreamID][0].Data).To(HaveLen(int(origlen - frame.DataLen())))
				Expect(queue.frameMap[frame1.StreamID][0].Offset).To(Equal(frame.DataLen()))
			})

			It("only removes a frame from the queue after return all split parts", func() {
				queue.Push(frame1, false)
				Expect(queue.Len()).To(Equal(1))
				frame, err := queue.Pop(6)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).ToNot(BeNil())
				Expect(queue.Len()).To(Equal(1))
				frame, err = queue.Pop(100)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).ToNot(BeNil())
				Expect(queue.Len()).To(BeZero())
			})

			It("gets the whole data of a frame, when it was split", func() {
				length := frame1.DataLen()
				origdata := make([]byte, length)
				copy(origdata, frame1.Data)
				queue.Push(frame1, false)
				frame, err := queue.Pop(6)
				Expect(err).ToNot(HaveOccurred())
				nextframe, err := queue.Pop(1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.DataLen() + nextframe.DataLen()).To(Equal(length))
				data := make([]byte, length)
				copy(data, frame.Data)
				copy(data[int(frame.DataLen()):], nextframe.Data)
				Expect(data).To(Equal(origdata))
			})

			It("correctly calculates the byte length when returning a split frame", func() {
				queue.Push(frame1, false)
				queue.Push(frame2, false)
				startByteLength := queue.ByteLen()
				frame, err := queue.Pop(6)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(frame1.StreamID)) // make sure the right frame was popped
				Expect(queue.ByteLen()).To(Equal(startByteLength - frame.DataLen()))
			})

			It("does not change the length of the queue when returning a split frame", func() {
				queue.Push(frame1, false)
				queue.Push(frame2, false)
				frame, err := queue.Pop(6)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(frame1.StreamID)) // make sure the right frame was popped
				Expect(queue.Len()).To(Equal(2))
			})
		})
	})

	Context("deleting streams", func() {
		It("deletes prioFrames", func() {
			queue.Push(prioFrame1, true)
			queue.Push(prioFrame2, true)
			queue.RemoveStream(prioFrame1.StreamID)
			frame, err := queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(prioFrame2))
			frame, err = queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeNil())
		})

		It("deletes multiple prioFrames from different streams", func() {
			queue.Push(prioFrame1, true)
			queue.Push(prioFrame2, true)
			queue.RemoveStream(prioFrame1.StreamID)
			queue.RemoveStream(prioFrame2.StreamID)
			frame, err := queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeNil())
		})

		It("deletes the map entry", func() {
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			Expect(queue.frameMap).To(HaveKey(frame1.StreamID))
			queue.RemoveStream(frame1.StreamID)
			Expect(queue.frameMap).ToNot(HaveKey(frame1.StreamID))
		})

		It("gets a normal frame, when the stream of the prio frame was deleted", func() {
			queue.Push(prioFrame1, true)
			queue.Push(frame1, true)
			queue.RemoveStream(prioFrame1.StreamID)
			frame, err := queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(frame1))
			frame, err = queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeNil())
		})

		It("deletes frames", func() {
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			queue.RemoveStream(frame1.StreamID)
			frame, err := queue.Pop(1000)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(frame2))
		})

		Context("garbage collection of activeStreams", func() {
			It("adjusts the activeStreams slice", func() {
				queue.activeStreams = []protocol.StreamID{5, 6, 10, 2, 3}
				queue.RemoveStream(10)
				Expect(queue.activeStreams).To(Equal([]protocol.StreamID{5, 6, 2, 3}))
			})

			It("garbage collects correctly if there is only one stream", func() {
				queue.activeStreams = []protocol.StreamID{10}
				queue.RemoveStream(10)
				Expect(queue.activeStreams).To(BeEmpty())
				Expect(queue.activeStreamsPosition).To(Equal(0))
			})

			It("does not change the scheduling, when the stream deleted is after the current position in activeStreams", func() {
				queue.activeStreams = []protocol.StreamID{5, 6, 10, 2, 3}
				queue.activeStreamsPosition = 0 // the next frame would be from Stream 5
				queue.RemoveStream(10)
				Expect(queue.activeStreamsPosition).To(Equal(0))
			})

			It("makes sure that scheduling is adjusted, if the stream deleted is before the current position in activeStreams", func() {
				queue.activeStreams = []protocol.StreamID{5, 6, 10, 2, 3}
				queue.activeStreamsPosition = 3 // the next frame would be from Stream 2
				queue.RemoveStream(10)
				Expect(queue.activeStreamsPosition).To(Equal(2))
			})

			It("makes sure that scheduling is adjusted, when a frame from the deleted stream was scheduled", func() {
				queue.activeStreams = []protocol.StreamID{5, 6, 10, 2, 3}
				queue.activeStreamsPosition = 2 // the next frame would be from Stream 10
				queue.RemoveStream(10)
				Expect(queue.activeStreamsPosition).To(Equal(2)) // the next frame will be from Stream 2
			})
		})
	})
})
