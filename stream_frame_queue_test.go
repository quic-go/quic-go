package quic

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("streamFrameQueue", func() {
	var prioFrame1, prioFrame2 *frames.StreamFrame
	var frame1, frame2 *frames.StreamFrame
	var queue *streamFrameQueue

	BeforeEach(func() {
		queue = &streamFrameQueue{}
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
	})

	It("sets the DataLenPresent on all StreamFrames", func() {
		queue.Push(frame1, false)
		queue.Push(prioFrame1, true)
		Expect(queue.frames[0].DataLenPresent).To(BeTrue())
		Expect(queue.prioFrames[0].DataLenPresent).To(BeTrue())
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

		It("does not change the length when using front()", func() {
			queue.Push(prioFrame1, true)
			queue.Push(frame1, false)
			Expect(queue.Len()).To(Equal(2))
			queue.front()
			Expect(queue.Len()).To(Equal(2))
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

		It("does not change the byte length when using front()", func() {
			queue.Push(prioFrame1, true)
			queue.Push(frame1, false)
			length := protocol.ByteCount(len(prioFrame1.Data) + len(frame1.Data))
			Expect(queue.ByteLen()).To(Equal(length))
			queue.front()
			Expect(queue.ByteLen()).To(Equal(length))
		})
	})

	Context("Popping", func() {
		It("returns nil when popping an empty queue", func() {
			Expect(queue.Pop(1000)).To(BeNil())
		})

		It("deletes elements once they are popped", func() {
			queue.Push(frame1, false)
			Expect(queue.Pop(1000)).To(Equal(frame1))
			Expect(queue.Pop(1000)).To(BeNil())
		})

		It("returns normal frames if no prio frames are available", func() {
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			Expect(queue.Pop(1000)).To(Equal(frame1))
			Expect(queue.Pop(1000)).To(Equal(frame2))
		})

		It("returns prio frames first", func() {
			queue.Push(prioFrame1, true)
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			queue.Push(prioFrame2, true)
			frame := queue.Pop(1000)
			Expect(frame).To(Equal(prioFrame1))
			frame = queue.Pop(1000)
			Expect(frame).To(Equal(prioFrame2))
			frame = queue.Pop(1000)
			Expect(frame).To(Equal(frame1))
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
				frame := queue.Pop(6)
				minLength, _ := frame.MinLength()
				Expect(int(minLength) - 1 + len(frame.Data)).To(Equal(6))
				Expect(queue.frames[0].Data).To(HaveLen(origlen - len(frame.Data)))
				Expect(queue.frames[0].Offset).To(Equal(protocol.ByteCount(len(frame.Data))))
			})

			It("only removes a frame from the queue after return all split parts", func() {
				queue.Push(frame1, false)
				Expect(queue.Len()).To(Equal(1))
				frame := queue.Pop(6)
				Expect(frame).ToNot(BeNil())
				Expect(queue.Len()).To(Equal(1))
				frame = queue.Pop(100)
				Expect(frame).ToNot(BeNil())
				Expect(queue.Len()).To(BeZero())
			})

			It("gets the whole data of a frame, when it was split", func() {
				length := len(frame1.Data)
				origdata := make([]byte, length)
				copy(origdata, frame1.Data)
				queue.Push(frame1, false)
				frame := queue.Pop(6)
				nextframe := queue.Pop(1000)
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
				frame := queue.Pop(6)
				Expect(frame.StreamID).To(Equal(frame1.StreamID)) // make sure the right frame was popped
				Expect(queue.ByteLen()).To(Equal(startByteLength - protocol.ByteCount(len(frame.Data))))
			})

			It("does not change the length of the queue when returning a split frame", func() {
				queue.Push(frame1, false)
				queue.Push(frame2, false)
				frame := queue.Pop(6)
				Expect(frame.StreamID).To(Equal(frame1.StreamID)) // make sure the right frame was popped
				Expect(queue.Len()).To(Equal(2))
			})
		})
	})

	Context("Front", func() {
		It("returns nil for an empty queue", func() {
			Expect(queue.front()).To(BeNil())
		})

		It("returns normal frames if no prio frames are available", func() {
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			frame, isPrioFrame := queue.front()
			Expect(isPrioFrame).To(BeFalse())
			Expect(frame).To(Equal(frame1))
			frame, isPrioFrame = queue.front()
			Expect(isPrioFrame).To(BeFalse())
			Expect(frame).To(Equal(frame1))
		})

		It("returns prio frames first", func() {
			queue.Push(prioFrame1, true)
			queue.Push(frame1, false)
			queue.Push(frame2, false)
			queue.Push(prioFrame2, true)
			frame, isPrioFrame := queue.front()
			Expect(isPrioFrame).To(BeTrue())
			Expect(frame).To(Equal(prioFrame1))
		})
	})
})
