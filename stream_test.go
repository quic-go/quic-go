package quic

import (
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream", func() {
	It("reads a single StreamFrame", func() {
		frame := frames.StreamFrame{
			Offset: 0,
			Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
		}
		stream := NewStream(nil, 1337)
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
		stream := NewStream(nil, 1337)
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
		stream := NewStream(nil, 1337)
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
		stream := NewStream(nil, 1337)
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
		stream := NewStream(nil, 1337)
		stream.AddStreamFrame(&frame1)
		stream.AddStreamFrame(&frame2)
		b := make([]byte, 4)
		n, err := stream.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(4))
		Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
	})

	It("waits until data is available", func() {
		stream := NewStream(nil, 1337)
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
		stream := NewStream(nil, 1337)
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
		stream := NewStream(nil, 1337)
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
		stream := NewStream(nil, 1337)
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
			stream := NewStream(nil, 1337)
			stream.AddStreamFrame(&frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			})
			f := stream.getNextFrameInOrder(true)
			Expect(f.Data).To(Equal([]byte{0xDE, 0xAD}))
		})

		It("waits for next frame", func() {
			stream := NewStream(nil, 1337)
			var b bool
			go func() {
				time.Sleep(time.Millisecond)
				b = true
				stream.AddStreamFrame(&frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD},
				})
			}()
			f := stream.getNextFrameInOrder(true)
			Expect(b).To(BeTrue())
			Expect(f.Data).To(Equal([]byte{0xDE, 0xAD}))
		})

		It("queues non-matching stream frames", func() {
			stream := NewStream(nil, 1337)
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
			f := stream.getNextFrameInOrder(true)
			Expect(b).To(BeTrue())
			Expect(f.Data).To(Equal([]byte{0xDE, 0xAD}))
			stream.ReadOffset += 2
			f = stream.getNextFrameInOrder(true)
			Expect(f.Data).To(Equal([]byte{0xBE, 0xEF}))
		})

		It("returns nil if non-blocking", func() {
			stream := NewStream(nil, 1337)
			Expect(stream.getNextFrameInOrder(false)).To(BeNil())
		})

		It("returns properly if non-blocking", func() {
			stream := NewStream(nil, 1337)
			stream.AddStreamFrame(&frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			})
			Expect(stream.getNextFrameInOrder(false)).ToNot(BeNil())
		})

		It("dequeues 3rd frame after blocking on 1st", func() {
			stream := NewStream(nil, 1337)
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
})
