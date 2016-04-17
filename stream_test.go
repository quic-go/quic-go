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

	PIt("rejects StreamFrames with wrong Offsets", func() {
		frame1 := frames.StreamFrame{
			Offset: 0,
			Data:   []byte{0xDE, 0xAD},
		}
		frame2 := frames.StreamFrame{
			Offset: 1,
			Data:   []byte{0xBE, 0xEF},
		}
		stream := NewStream(nil, 1337)
		stream.AddStreamFrame(&frame1)
		err := stream.AddStreamFrame(&frame2)
		Expect(err).To(HaveOccurred())
	})
})
