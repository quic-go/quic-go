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
			b := bytes.NewReader([]byte{0x40, 0x1a, 0x8e, 0x0, 0x1a, 0x1, 0x1, 0x6b, 0x26, 0x3, 0x0})
			frame, err := ParseAckFrameNew(b, protocol.Version34)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(0x1a)))
			Expect(frame.DelayTime).To(Equal(142 * time.Microsecond))
			Expect(frame.HasNACK()).To(Equal(false))
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with a 48 bit packet number", func() {
			b := bytes.NewReader([]byte{0x4c, 0x37, 0x13, 0xad, 0xfb, 0xca, 0xde, 0x0, 0x0, 0x0, 0x1, 0, 0, 0, 0, 0})
			frame, err := ParseAckFrameNew(b, protocol.Version32)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(0xdecafbad1337)))
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with multiple timestamps", func() {
			b := bytes.NewReader([]byte{0x40, 0x10, 0x0, 0x0, 0x10, 0x4, 0x1, 0x6b, 0x26, 0x4, 0x0, 0x3, 0, 0, 0x2, 0, 0, 0x1, 0, 0})
			_, err := ParseAckFrameNew(b, protocol.Version34)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(BeZero())
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
