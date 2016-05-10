package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("StreamFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0xa0, 0x1, 0x06, 0x00, 'f', 'o', 'o', 'b', 'a', 'r'})
			frame, err := ParseStreamFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.FinBit).To(BeFalse())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(1)))
			Expect(frame.Offset).To(BeZero())
			Expect(frame.Data).To(Equal([]byte("foobar")))
		})

		It("accepts frame without datalength", func() {
			b := bytes.NewReader([]byte{0x80, 0x1, 'f', 'o', 'o', 'b', 'a', 'r'})
			frame, err := ParseStreamFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.FinBit).To(BeFalse())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(1)))
			Expect(frame.Offset).To(BeZero())
			Expect(frame.Data).To(Equal([]byte("foobar")))
		})
	})

	Context("when writing", func() {
		It("writes sample frame", func() {
			b := &bytes.Buffer{}
			(&StreamFrame{
				StreamID: 1,
				Data:     []byte("foobar"),
			}).Write(b, 1, protocol.PacketNumberLen6, 0)
			Expect(b.Bytes()).To(Equal([]byte{0xa0, 0x1, 0x06, 0x00, 'f', 'o', 'o', 'b', 'a', 'r'}))
		})

		It("writes offsets", func() {
			b := &bytes.Buffer{}
			(&StreamFrame{
				StreamID: 1,
				Offset:   16,
				Data:     []byte("foobar"),
			}).Write(b, 1, protocol.PacketNumberLen6, 0)
			Expect(b.Bytes()).To(Equal([]byte{0xbc, 0x1, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x06, 0x00, 'f', 'o', 'o', 'b', 'a', 'r'}))
		})

		It("has proper min length", func() {
			b := &bytes.Buffer{}
			f := &StreamFrame{
				StreamID: 1,
				Data:     []byte("f"),
				Offset:   1,
			}
			f.Write(b, 1, protocol.PacketNumberLen6, 0)
			Expect(f.MinLength()).To(Equal(protocol.ByteCount(b.Len())))
		})

		Context("lengths of StreamIDs", func() {
			It("writes a 2 byte StreamID", func() {
				b := &bytes.Buffer{}
				(&StreamFrame{
					StreamID: 13,
					Data:     []byte("foobar"),
				}).Write(b, 1, protocol.PacketNumberLen6, 0)
				Expect(b.Bytes()[0] & 0x3).To(Equal(uint8(0x0)))
				Expect(b.Bytes()[1]).To(Equal(uint8(13)))
			})

			It("writes a 2 byte StreamID", func() {
				b := &bytes.Buffer{}
				(&StreamFrame{
					StreamID: 0xCAFE,
					Data:     []byte("foobar"),
				}).Write(b, 1, protocol.PacketNumberLen6, 0)
				Expect(b.Bytes()[0] & 0x3).To(Equal(uint8(0x1)))
				Expect(b.Bytes()[1:3]).To(Equal([]byte{0xFE, 0xCA}))
			})

			It("writes a 3 byte StreamID", func() {
				b := &bytes.Buffer{}
				(&StreamFrame{
					StreamID: 0x13BEEF,
					Data:     []byte("foobar"),
				}).Write(b, 1, protocol.PacketNumberLen6, 0)
				Expect(b.Bytes()[0] & 0x3).To(Equal(uint8(0x2)))
				Expect(b.Bytes()[1:4]).To(Equal([]byte{0xEF, 0xBE, 0x13}))
			})

			It("writes a 4 byte StreamID", func() {
				b := &bytes.Buffer{}
				(&StreamFrame{
					StreamID: 0xDECAFBAD,
					Data:     []byte("foobar"),
				}).Write(b, 1, protocol.PacketNumberLen6, 0)
				Expect(b.Bytes()[0] & 0x3).To(Equal(uint8(0x3)))
				Expect(b.Bytes()[1:5]).To(Equal([]byte{0xAD, 0xFB, 0xCA, 0xDE}))
			})
		})
	})

	Context("shortening of StreamIDs", func() {
		It("determines the length of a 1 byte StreamID", func() {
			f := &StreamFrame{StreamID: 0xFF}
			f.calculateStreamIDLength()
			Expect(f.streamIDLen).To(Equal(protocol.ByteCount(1)))
		})

		It("determines the length of a 2 byte StreamID", func() {
			f := &StreamFrame{StreamID: 0xFFFF}
			f.calculateStreamIDLength()
			Expect(f.streamIDLen).To(Equal(protocol.ByteCount(2)))
		})

		It("determines the length of a 1 byte StreamID", func() {
			f := &StreamFrame{StreamID: 0xFFFFFF}
			f.calculateStreamIDLength()
			Expect(f.streamIDLen).To(Equal(protocol.ByteCount(3)))
		})

		It("determines the length of a 1 byte StreamID", func() {
			f := &StreamFrame{StreamID: 0xFFFFFFFF}
			f.calculateStreamIDLength()
			Expect(f.streamIDLen).To(Equal(protocol.ByteCount(4)))
		})
	})

	Context("splitting off earlier stream frames", func() {
		It("splits off nothing", func() {
			f := &StreamFrame{
				StreamID: 1,
				Data:     []byte("bar"),
				Offset:   3,
			}
			Expect(f.MaybeSplitOffFrame(1000)).To(BeNil())
			Expect(f.Offset).To(Equal(protocol.ByteCount(3)))
		})

		It("splits off initial frame", func() {
			f := &StreamFrame{
				StreamID: 1,
				Data:     []byte("foobar"),
				Offset:   3,
				FinBit:   true,
			}
			previous := f.MaybeSplitOffFrame(f.MinLength() - 1 + 3)
			Expect(previous).ToNot(BeNil())
			Expect(previous.StreamID).To(Equal(protocol.StreamID(1)))
			Expect(previous.Data).To(Equal([]byte("foo")))
			Expect(previous.Offset).To(Equal(protocol.ByteCount(3)))
			Expect(previous.FinBit).To(BeFalse())
			Expect(f.StreamID).To(Equal(protocol.StreamID(1)))
			Expect(f.Data).To(Equal([]byte("bar")))
			Expect(f.Offset).To(Equal(protocol.ByteCount(6)))
			Expect(f.FinBit).To(BeTrue())
		})
	})
})
