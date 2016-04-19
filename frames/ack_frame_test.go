package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AckFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x40, 0xA4, 0x03, 0x23, 0x45, 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC})
			frame, err := ParseAckFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Entropy).To(Equal(byte(0xA4)))
			Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(0x03)))
			Expect(frame.DelayTime).To(Equal(uint16(0x4523)))
			Expect(frame.HasNACK).To(Equal(false))
			Expect(b.Len()).To(Equal(0))
		})

		It("parses a frame with a 48 bit packet number", func() {
			b := bytes.NewReader([]byte{0x4C, 0xA4, 0x37, 0x13, 0xAD, 0xFB, 0xCA, 0xDE, 0x23, 0x45, 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC})
			frame, err := ParseAckFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(0xDECAFBAD1337)))
			Expect(b.Len()).To(Equal(0))
		})

		It("completely parses a frame with multiple timestamps", func() {
			b := bytes.NewReader([]byte{0x40, 0xA4, 0x03, 0x23, 0x45, 0x03, 0x02, 0xFF, 0xEE, 0xDD, 0xCC, 0x12, 0x34, 0x56, 0x78, 0x90, 0xA0})
			_, err := ParseAckFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(0))
		})

		It("parses a frame containing one NACK range", func() {
			b := bytes.NewReader([]byte{0x60, 0x8, 0x3, 0x72, 0x1, 0x1, 0x0, 0xc0, 0x15, 0x0, 0x0, 0x1, 0x1, 0x1})
			frame, err := ParseAckFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.HasNACK).To(Equal(true))
			Expect(len(frame.NackRanges)).To(Equal(1))
			Expect(frame.NackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(frame.NackRanges[0].Length).To(Equal(uint8(2)))
		})

		It("parses a frame containing multiple NACK ranges", func() {
			b := bytes.NewReader([]byte{0x60, 0x2, 0xf, 0xb8, 0x1, 0x1, 0x0, 0xe5, 0x58, 0x4, 0x0, 0x3, 0x1, 0x6, 0x1, 0x2, 0x1, 0x0})
			frame, err := ParseAckFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.HasNACK).To(Equal(true))
			Expect(len(frame.NackRanges)).To(Equal(3))
			Expect(frame.NackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(8)))
			Expect(frame.NackRanges[0].Length).To(Equal(uint8(7)))
			Expect(frame.NackRanges[1].FirstPacketNumber).To(Equal(protocol.PacketNumber(4)))
			Expect(frame.NackRanges[1].Length).To(Equal(uint8(3)))
			Expect(frame.NackRanges[2].FirstPacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(frame.NackRanges[2].Length).To(Equal(uint8(1)))
		})
	})

	Context("when writing", func() {
		It("writes simple frames", func() {
			b := &bytes.Buffer{}
			(&AckFrame{
				Entropy:         2,
				LargestObserved: 1,
			}).Write(b)
			Expect(b.Bytes()).To(Equal([]byte{0x48, 0x02, 0x01, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0}))
		})
	})

	It("is self-consistent", func() {
		b := &bytes.Buffer{}
		frame := &AckFrame{
			Entropy:         0xDE,
			LargestObserved: 6789,
		}
		err := frame.Write(b)
		Expect(err).ToNot(HaveOccurred())
		readframe, err := ParseAckFrame(bytes.NewReader(b.Bytes()))
		Expect(err).ToNot(HaveOccurred())
		Expect(readframe.Entropy).To(Equal(frame.Entropy))
		Expect(readframe.LargestObserved).To(Equal(frame.LargestObserved))
	})
})
