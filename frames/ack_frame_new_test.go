package frames

import (
	"bytes"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AckFrame", func() {
	Context("when parsing", func() {
		It("accepts a sample frame", func() {
			b := bytes.NewReader([]byte{0x40, 0x1c, 0x8e, 0x0, 0x1c, 0x1, 0x1, 0x6b, 0x26, 0x3, 0x0})
			frame, err := ParseAckFrameNew(b, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(0x1c)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
			Expect(frame.DelayTime).To(Equal(142 * time.Microsecond))
			Expect(frame.HasNACK()).To(Equal(false))
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with a 48 bit packet number", func() {
			b := bytes.NewReader([]byte{0x4c, 0x37, 0x13, 0xad, 0xfb, 0xca, 0xde, 0x0, 0x0, 0x0, 0x1, 0, 0, 0, 0, 0})
			frame, err := ParseAckFrameNew(b, protocol.Version34)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(0xdecafbad1337)))
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with multiple timestamps", func() {
			b := bytes.NewReader([]byte{0x40, 0x10, 0x0, 0x0, 0x10, 0x4, 0x1, 0x6b, 0x26, 0x4, 0x0, 0x3, 0, 0, 0x2, 0, 0, 0x1, 0, 0})
			_, err := ParseAckFrameNew(b, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(BeZero())
		})

		It("errors when the ACK range is too large", func() {
			// LargestObserved: 0x1c
			// Length: 0x1d => LowestAcked would be -1
			b := bytes.NewReader([]byte{0x40, 0x1c, 0x8e, 0x0, 0x1d, 0x1, 0x1, 0x6b, 0x26, 0x3, 0x0})
			_, err := ParseAckFrameNew(b, 0)
			Expect(err).To(MatchError(errInvalidAckRanges))
		})

		Context("ACK blocks", func() {
			It("parses a frame with one ACK block", func() {
				b := bytes.NewReader([]byte{0x60, 0x18, 0x94, 0x1, 0x1, 0x3, 0x2, 0x13, 0x2, 0x1, 0x5c, 0xd5, 0x0, 0x0, 0x0, 0x95, 0x0})
				frame, err := ParseAckFrameNew(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(24)))
				Expect(frame.AckRanges).To(HaveLen(2))
				Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 22, LastPacketNumber: 24}))
				Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 1, LastPacketNumber: 19}))
				Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
				Expect(b.Len()).To(BeZero())
			})

			It("parses a frame with multiple single packets missing", func() {
				b := bytes.NewReader([]byte{0x60, 0x27, 0xda, 0x0, 0x6, 0x9, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x13, 0x2, 0x1, 0x71, 0x12, 0x3, 0x0, 0x0, 0x47, 0x2})
				frame, err := ParseAckFrameNew(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(0x27)))
				Expect(frame.AckRanges).To(HaveLen(7))
				Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 31, LastPacketNumber: 0x27}))
				Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 29, LastPacketNumber: 29}))
				Expect(frame.AckRanges[2]).To(Equal(AckRange{FirstPacketNumber: 27, LastPacketNumber: 27}))
				Expect(frame.AckRanges[3]).To(Equal(AckRange{FirstPacketNumber: 25, LastPacketNumber: 25}))
				Expect(frame.AckRanges[4]).To(Equal(AckRange{FirstPacketNumber: 23, LastPacketNumber: 23}))
				Expect(frame.AckRanges[5]).To(Equal(AckRange{FirstPacketNumber: 21, LastPacketNumber: 21}))
				Expect(frame.AckRanges[6]).To(Equal(AckRange{FirstPacketNumber: 1, LastPacketNumber: 19}))
				Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
				Expect(b.Len()).To(BeZero())
			})

			It("parses a frame with multiple longer ACK blocks", func() {
				b := bytes.NewReader([]byte{0x60, 0x52, 0xd1, 0x0, 0x3, 0x17, 0xa, 0x10, 0x4, 0x8, 0x2, 0x13, 0x2, 0x1, 0x6c, 0xc8, 0x2, 0x0, 0x0, 0x7e, 0x1})
				frame, err := ParseAckFrameNew(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(0x52)))
				Expect(frame.AckRanges).To(HaveLen(4))
				Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 60, LastPacketNumber: 0x52}))
				Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 34, LastPacketNumber: 49}))
				Expect(frame.AckRanges[2]).To(Equal(AckRange{FirstPacketNumber: 22, LastPacketNumber: 29}))
				Expect(frame.AckRanges[3]).To(Equal(AckRange{FirstPacketNumber: 1, LastPacketNumber: 19}))
				Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
				Expect(b.Len()).To(BeZero())
			})
		})
	})

	Context("when writing", func() {
		var b *bytes.Buffer
		BeforeEach(func() {
			b = &bytes.Buffer{}
		})

		Context("min length", func() {
			It("has proper min length", func() {
				f := &AckFrameNew{
					LargestObserved: 1,
				}
				f.Write(b, 0)
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has proper min length with a large LargestObserved", func() {
				f := &AckFrameNew{
					LargestObserved: 0xDEADBEEFCAFE,
				}
				f.Write(b, 0)
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})
		})
	})

	Context("highest in order packet number", func() {
		It("gets the hightest in order packet number for a simple ACK", func() {
			frame := &AckFrameNew{
				LargestObserved: 0x1337,
			}
			Expect(frame.GetHighestInOrderPacketNumber()).To(Equal(protocol.PacketNumber(0x1337)))
		})

	})

	Context("self-consistency checks", func() {
		var b *bytes.Buffer
		BeforeEach(func() {
			b = &bytes.Buffer{}
		})

		It("is self-consistent for ACK frames without NACK ranges", func() {
			frameOrig := &AckFrameNew{
				LargestObserved: 1,
			}
			err := frameOrig.Write(b, protocol.Version34)
			Expect(err).ToNot(HaveOccurred())
			r := bytes.NewReader(b.Bytes())
			frame, err := ParseAckFrameNew(r, protocol.Version34)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(frameOrig.LargestObserved))
			Expect(r.Len()).To(BeZero())
		})
	})
})
