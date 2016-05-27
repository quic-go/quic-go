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
	})

	Context("Queue Byte Length", func() {
		It("returns the correct length for an empty queue", func() {
			Expect(queue.ByteLen()).To(BeZero())
		})

		It("returns the correct byte length for a queue", func() {
			queue.Push(prioFrame1, true)
			Expect(queue.ByteLen()).To(Equal(protocol.ByteCount(2)))
			queue.Push(frame2, false)
			Expect(queue.ByteLen()).To(Equal(protocol.ByteCount(len(prioFrame1.Data) + len(frame2.Data))))
		})

		It("returns the correct byte length when popping", func() {
			queue.Push(prioFrame1, true)
			queue.Push(frame1, false)
			Expect(queue.ByteLen()).To(Equal(protocol.ByteCount(len(prioFrame1.Data) + len(frame1.Data))))
			queue.Pop(1000)
			Expect(queue.ByteLen()).To(Equal(protocol.ByteCount(len(frame1.Data))))
			queue.Pop(1000)
			Expect(queue.ByteLen()).To(Equal(protocol.ByteCount(0)))
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
			length := protocol.ByteCount(len(prioFrame1.Data) + len(frame1.Data))
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
				origlen := len(frame1.Data)
				frame, err := queue.Pop(6)
				Expect(err).ToNot(HaveOccurred())
				minLength, _ := frame.MinLength()
				Expect(int(minLength) - 1 + len(frame.Data)).To(Equal(6))
				Expect(queue.frameMap[frame1.StreamID][0].Data).To(HaveLen(origlen - len(frame.Data)))
				Expect(queue.frameMap[frame1.StreamID][0].Offset).To(Equal(protocol.ByteCount(len(frame.Data))))
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
				length := len(frame1.Data)
				origdata := make([]byte, length)
				copy(origdata, frame1.Data)
				queue.Push(frame1, false)
				frame, err := queue.Pop(6)
				Expect(err).ToNot(HaveOccurred())
				nextframe, err := queue.Pop(1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(frame.Data) + len(nextframe.Data)).To(Equal(length))
				data := make([]byte, length)
				copy(data, frame.Data)
				copy(data[len(frame.Data):], nextframe.Data)
				Expect(data).To(Equal(origdata))
			})

			It("correctly calculates the byte length when returning a split frame", func() {
				queue.Push(frame1, false)
				queue.Push(frame2, false)
				startByteLength := queue.ByteLen()
				frame, err := queue.Pop(6)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(frame1.StreamID)) // make sure the right frame was popped
				Expect(queue.ByteLen()).To(Equal(startByteLength - protocol.ByteCount(len(frame.Data))))
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
})
