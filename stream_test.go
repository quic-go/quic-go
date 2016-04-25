package quic

import (
	"errors"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockStreamHandler struct {
	closedStream bool
}

func (*mockStreamHandler) QueueFrame(frames.Frame) error {
	panic("not implemented")
}

func (m *mockStreamHandler) closeStream(protocol.StreamID) {
	m.closedStream = true
}

var _ = Describe("Stream", func() {
	var (
		stream  *Stream
		handler *mockStreamHandler
	)

	BeforeEach(func() {
		handler = &mockStreamHandler{}
		stream = NewStream(handler, 1337)
	})

	It("reads a single StreamFrame", func() {
		frame := frames.StreamFrame{
			Offset: 0,
			Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
		}
		stream.AddStreamFrame(&frame)
		b := make([]byte, 4)
		n, err := stream.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(4))
		Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
	})

	It("reads a single StreamFrame in multiple goes", func() {
		frame := frames.StreamFrame{
			Offset: 0,
			Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
		}
		stream.AddStreamFrame(&frame)
		b := make([]byte, 2)
		n, err := stream.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(2))
		Expect(b).To(Equal([]byte{0xDE, 0xAD}))
		n, err = stream.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(2))
		Expect(b).To(Equal([]byte{0xBE, 0xEF}))
	})

	It("reads single bytes", func() {
		frame := frames.StreamFrame{
			Offset: 0,
			Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
		}
		stream.AddStreamFrame(&frame)
		b, err := stream.ReadByte()
		Expect(err).ToNot(HaveOccurred())
		Expect(b).To(Equal(byte(0xDE)))
		b, err = stream.ReadByte()
		Expect(err).ToNot(HaveOccurred())
		Expect(b).To(Equal(byte(0xAD)))
		b, err = stream.ReadByte()
		Expect(err).ToNot(HaveOccurred())
		Expect(b).To(Equal(byte(0xBE)))
		b, err = stream.ReadByte()
		Expect(err).ToNot(HaveOccurred())
		Expect(b).To(Equal(byte(0xEF)))
	})

	It("reads all data available", func() {
		frame1 := frames.StreamFrame{
			Offset: 0,
			Data:   []byte{0xDE, 0xAD},
		}
		frame2 := frames.StreamFrame{
			Offset: 2,
			Data:   []byte{0xBE, 0xEF},
		}
		stream.AddStreamFrame(&frame1)
		stream.AddStreamFrame(&frame2)
		b := make([]byte, 6)
		n, err := stream.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(4))
		Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00}))
	})

	It("assembles multiple StreamFrames", func() {
		frame1 := frames.StreamFrame{
			Offset: 0,
			Data:   []byte{0xDE, 0xAD},
		}
		frame2 := frames.StreamFrame{
			Offset: 2,
			Data:   []byte{0xBE, 0xEF},
		}
		stream.AddStreamFrame(&frame1)
		stream.AddStreamFrame(&frame2)
		b := make([]byte, 4)
		n, err := stream.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(4))
		Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
	})

	It("waits until data is available", func() {
		go func() {
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			}
			time.Sleep(time.Millisecond)
			stream.AddStreamFrame(&frame)
		}()
		b := make([]byte, 2)
		n, err := stream.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(2))
	})

	It("handles StreamFrames in wrong order", func() {
		frame1 := frames.StreamFrame{
			Offset: 2,
			Data:   []byte{0xBE, 0xEF},
		}
		frame2 := frames.StreamFrame{
			Offset: 0,
			Data:   []byte{0xDE, 0xAD},
		}
		stream.AddStreamFrame(&frame1)
		stream.AddStreamFrame(&frame2)
		b := make([]byte, 4)
		n, err := stream.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(4))
		Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
	})

	It("handles duplicate StreamFrames", func() {
		frame1 := frames.StreamFrame{
			Offset: 0,
			Data:   []byte{0xDE, 0xAD},
		}
		frame2 := frames.StreamFrame{
			Offset: 0,
			Data:   []byte{0xDE, 0xAD},
		}
		frame3 := frames.StreamFrame{
			Offset: 2,
			Data:   []byte{0xBE, 0xEF},
		}
		stream.AddStreamFrame(&frame1)
		stream.AddStreamFrame(&frame2)
		stream.AddStreamFrame(&frame3)
		b := make([]byte, 4)
		n, err := stream.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(4))
		Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
	})

	It("discards unneeded stream frames", func() {
		frame1 := frames.StreamFrame{
			Offset: 0,
			Data:   []byte{0xDE, 0xAD},
		}
		frame2 := frames.StreamFrame{
			Offset: 1,
			Data:   []byte{0x42, 0x24},
		}
		frame3 := frames.StreamFrame{
			Offset: 2,
			Data:   []byte{0xBE, 0xEF},
		}
		stream.AddStreamFrame(&frame1)
		stream.AddStreamFrame(&frame2)
		stream.AddStreamFrame(&frame3)
		b := make([]byte, 4)
		n, err := stream.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(4))
		Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
	})

	Context("getting next stream frame", func() {
		It("gets next frame", func() {
			stream.AddStreamFrame(&frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			})
			f, err := stream.getNextFrameInOrder(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Data).To(Equal([]byte{0xDE, 0xAD}))
		})

		It("waits for next frame", func() {
			var b bool
			go func() {
				time.Sleep(time.Millisecond)
				b = true
				stream.AddStreamFrame(&frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD},
				})
			}()
			f, err := stream.getNextFrameInOrder(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(BeTrue())
			Expect(f.Data).To(Equal([]byte{0xDE, 0xAD}))
		})

		It("queues non-matching stream frames", func() {
			var b bool
			stream.AddStreamFrame(&frames.StreamFrame{
				Offset: 2,
				Data:   []byte{0xBE, 0xEF},
			})
			go func() {
				time.Sleep(time.Millisecond)
				b = true
				stream.AddStreamFrame(&frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD},
				})
			}()
			f, err := stream.getNextFrameInOrder(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(BeTrue())
			Expect(f.Data).To(Equal([]byte{0xDE, 0xAD}))
			stream.ReadOffset += 2
			f, err = stream.getNextFrameInOrder(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Data).To(Equal([]byte{0xBE, 0xEF}))
		})

		It("returns nil if non-blocking", func() {
			Expect(stream.getNextFrameInOrder(false)).To(BeNil())
		})

		It("returns properly if non-blocking", func() {
			stream.AddStreamFrame(&frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			})
			Expect(stream.getNextFrameInOrder(false)).ToNot(BeNil())
		})

		It("dequeues 3rd frame after blocking on 1st", func() {
			stream.AddStreamFrame(&frames.StreamFrame{
				Offset: 4,
				Data:   []byte{0x23, 0x42},
			})
			stream.AddStreamFrame(&frames.StreamFrame{
				Offset: 2,
				Data:   []byte{0xBE, 0xEF},
			})
			go func() {
				time.Sleep(time.Millisecond)
				stream.AddStreamFrame(&frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD},
				})
			}()
			Expect(stream.getNextFrameInOrder(true)).ToNot(BeNil())
			stream.ReadOffset += 2
			Expect(stream.getNextFrameInOrder(true)).ToNot(BeNil())
			stream.ReadOffset += 2
			Expect(stream.getNextFrameInOrder(true)).ToNot(BeNil())
		})
	})

	Context("closing", func() {
		AfterEach(func() {
			Expect(stream.StreamFrames).To(BeClosed())
			Expect(handler.closedStream).To(BeTrue())
		})

		Context("with fin bit", func() {
			It("returns EOFs", func() {
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
					FinBit: true,
				}
				stream.AddStreamFrame(&frame)
				b := make([]byte, 4)
				n, err := stream.Read(b)
				Expect(err).To(Equal(io.EOF))
				Expect(n).To(Equal(4))
				Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
				n, err = stream.Read(b)
				Expect(n).To(BeZero())
				Expect(err).To(Equal(io.EOF))
			})

			It("handles out-of-order frames", func() {
				frame1 := frames.StreamFrame{
					Offset: 2,
					Data:   []byte{0xBE, 0xEF},
					FinBit: true,
				}
				frame2 := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD},
				}
				stream.AddStreamFrame(&frame1)
				stream.AddStreamFrame(&frame2)
				b := make([]byte, 4)
				n, err := stream.Read(b)
				Expect(err).To(Equal(io.EOF))
				Expect(n).To(Equal(4))
				Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
				n, err = stream.Read(b)
				Expect(n).To(BeZero())
				Expect(err).To(Equal(io.EOF))
			})

			It("returns EOFs with partial read", func() {
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD},
					FinBit: true,
				}
				stream.AddStreamFrame(&frame)
				b := make([]byte, 4)
				n, err := stream.Read(b)
				Expect(err).To(Equal(io.EOF))
				Expect(n).To(Equal(2))
				Expect(b[:n]).To(Equal([]byte{0xDE, 0xAD}))
			})

			It("handles immediate FINs", func() {
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{},
					FinBit: true,
				}
				stream.AddStreamFrame(&frame)
				b := make([]byte, 4)
				n, err := stream.Read(b)
				Expect(n).To(BeZero())
				Expect(err).To(Equal(io.EOF))
			})
		})

		Context("with remote errors", func() {
			testErr := errors.New("test error")

			It("returns errors", func() {
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
				}
				stream.AddStreamFrame(&frame)
				stream.RegisterError(testErr)
				b := make([]byte, 4)
				n, err := stream.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(4))
				Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
				n, err = stream.Read(b)
				Expect(n).To(BeZero())
				Expect(err).To(Equal(testErr))
			})
		})
	})
})
