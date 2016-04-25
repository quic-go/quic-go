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
	frames       []frames.Frame
}

func (m *mockStreamHandler) QueueFrame(f frames.Frame) error {
	m.frames = append(m.frames, f)
	return nil
}

func (m *mockStreamHandler) closeStream(protocol.StreamID) {
	m.closedStream = true
}

var _ = Describe("Stream", func() {
	var (
		str     *stream
		handler *mockStreamHandler
	)

	BeforeEach(func() {
		handler = &mockStreamHandler{}
		str = newStream(handler, 1337)
	})

	Context("reading", func() {
		It("reads a single StreamFrame", func() {
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}
			str.AddStreamFrame(&frame)
			b := make([]byte, 4)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
		})

		It("reads a single StreamFrame in multiple goes", func() {
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}
			str.AddStreamFrame(&frame)
			b := make([]byte, 2)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(2))
			Expect(b).To(Equal([]byte{0xDE, 0xAD}))
			n, err = str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(2))
			Expect(b).To(Equal([]byte{0xBE, 0xEF}))
		})

		It("reads single bytes", func() {
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}
			str.AddStreamFrame(&frame)
			b, err := str.ReadByte()
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal(byte(0xDE)))
			b, err = str.ReadByte()
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal(byte(0xAD)))
			b, err = str.ReadByte()
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal(byte(0xBE)))
			b, err = str.ReadByte()
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
			str.AddStreamFrame(&frame1)
			str.AddStreamFrame(&frame2)
			b := make([]byte, 6)
			n, err := str.Read(b)
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
			str.AddStreamFrame(&frame1)
			str.AddStreamFrame(&frame2)
			b := make([]byte, 4)
			n, err := str.Read(b)
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
				str.AddStreamFrame(&frame)
			}()
			b := make([]byte, 2)
			n, err := str.Read(b)
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
			str.AddStreamFrame(&frame1)
			str.AddStreamFrame(&frame2)
			b := make([]byte, 4)
			n, err := str.Read(b)
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
			str.AddStreamFrame(&frame1)
			str.AddStreamFrame(&frame2)
			str.AddStreamFrame(&frame3)
			b := make([]byte, 4)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
		})

		It("discards unneeded str frames", func() {
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
			str.AddStreamFrame(&frame1)
			str.AddStreamFrame(&frame2)
			str.AddStreamFrame(&frame3)
			b := make([]byte, 4)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
		})
	})

	Context("writing", func() {
		It("writes str frames", func() {
			n, err := str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(6))
			Expect(handler.frames).To(HaveLen(1))
			Expect(handler.frames[0]).To(Equal(&frames.StreamFrame{
				StreamID: 1337,
				Data:     []byte("foobar"),
			}))
		})

		It("writes multiple str frames", func() {
			n, err := str.Write([]byte("foo"))
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(3))
			n, err = str.Write([]byte("bar"))
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(3))
			Expect(handler.frames).To(HaveLen(2))
			Expect(handler.frames[0]).To(Equal(&frames.StreamFrame{
				StreamID: 1337,
				Data:     []byte("foo"),
			}))
			Expect(handler.frames[1]).To(Equal(&frames.StreamFrame{
				StreamID: 1337,
				Data:     []byte("bar"),
				Offset:   3,
			}))
		})

		It("closes", func() {
			err := str.Close()
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.frames).To(HaveLen(1))
			Expect(handler.frames[0]).To(Equal(&frames.StreamFrame{
				StreamID: 1337,
				FinBit:   true,
				Offset:   0,
			}))
		})
	})

	Context("getting next str frame", func() {
		It("gets next frame", func() {
			str.AddStreamFrame(&frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			})
			f, err := str.getNextFrameInOrder(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Data).To(Equal([]byte{0xDE, 0xAD}))
		})

		It("waits for next frame", func() {
			var b bool
			go func() {
				time.Sleep(time.Millisecond)
				b = true
				str.AddStreamFrame(&frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD},
				})
			}()
			f, err := str.getNextFrameInOrder(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(BeTrue())
			Expect(f.Data).To(Equal([]byte{0xDE, 0xAD}))
		})

		It("queues non-matching str frames", func() {
			var b bool
			str.AddStreamFrame(&frames.StreamFrame{
				Offset: 2,
				Data:   []byte{0xBE, 0xEF},
			})
			go func() {
				time.Sleep(time.Millisecond)
				b = true
				str.AddStreamFrame(&frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD},
				})
			}()
			f, err := str.getNextFrameInOrder(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(BeTrue())
			Expect(f.Data).To(Equal([]byte{0xDE, 0xAD}))
			str.readOffset += 2
			f, err = str.getNextFrameInOrder(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Data).To(Equal([]byte{0xBE, 0xEF}))
		})

		It("returns nil if non-blocking", func() {
			Expect(str.getNextFrameInOrder(false)).To(BeNil())
		})

		It("returns properly if non-blocking", func() {
			str.AddStreamFrame(&frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			})
			Expect(str.getNextFrameInOrder(false)).ToNot(BeNil())
		})

		It("dequeues 3rd frame after blocking on 1st", func() {
			str.AddStreamFrame(&frames.StreamFrame{
				Offset: 4,
				Data:   []byte{0x23, 0x42},
			})
			str.AddStreamFrame(&frames.StreamFrame{
				Offset: 2,
				Data:   []byte{0xBE, 0xEF},
			})
			go func() {
				time.Sleep(time.Millisecond)
				str.AddStreamFrame(&frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD},
				})
			}()
			Expect(str.getNextFrameInOrder(true)).ToNot(BeNil())
			str.readOffset += 2
			Expect(str.getNextFrameInOrder(true)).ToNot(BeNil())
			str.readOffset += 2
			Expect(str.getNextFrameInOrder(true)).ToNot(BeNil())
		})
	})

	Context("closing", func() {
		AfterEach(func() {
			Expect(str.streamFrames).To(BeClosed())
			Expect(handler.closedStream).To(BeTrue())
		})

		Context("with fin bit", func() {
			It("returns EOFs", func() {
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
					FinBit: true,
				}
				str.AddStreamFrame(&frame)
				b := make([]byte, 4)
				n, err := str.Read(b)
				Expect(err).To(Equal(io.EOF))
				Expect(n).To(Equal(4))
				Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
				n, err = str.Read(b)
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
				str.AddStreamFrame(&frame1)
				str.AddStreamFrame(&frame2)
				b := make([]byte, 4)
				n, err := str.Read(b)
				Expect(err).To(Equal(io.EOF))
				Expect(n).To(Equal(4))
				Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
				n, err = str.Read(b)
				Expect(n).To(BeZero())
				Expect(err).To(Equal(io.EOF))
			})

			It("returns EOFs with partial read", func() {
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD},
					FinBit: true,
				}
				str.AddStreamFrame(&frame)
				b := make([]byte, 4)
				n, err := str.Read(b)
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
				str.AddStreamFrame(&frame)
				b := make([]byte, 4)
				n, err := str.Read(b)
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
				str.AddStreamFrame(&frame)
				str.RegisterError(testErr)
				b := make([]byte, 4)
				n, err := str.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(4))
				Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
				n, err = str.Read(b)
				Expect(n).To(BeZero())
				Expect(err).To(Equal(testErr))
			})
		})
	})
})
