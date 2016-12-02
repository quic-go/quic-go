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
			frame, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x1c)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
			Expect(frame.DelayTime).To(Equal(142 * time.Microsecond))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame without a timestamp", func() {
			b := bytes.NewReader([]byte{0x40, 0x3, 0x50, 0x15, 0x3, 0x0})
			frame, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(3)))
		})

		It("parses a frame where the largest acked is 0", func() {
			b := bytes.NewReader([]byte{0x40, 0x0, 0xff, 0xff, 0x0, 0x0})
			frame, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(0)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with a 48 bit packet number", func() {
			b := bytes.NewReader([]byte{0x4c, 0x37, 0x13, 0xad, 0xfb, 0xca, 0xde, 0x0, 0x0, 0x5, 0x1, 0, 0, 0, 0, 0})
			frame, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0xdecafbad1337)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(0xdecafbad1337 - 5 + 1)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with 1 ACKed packet", func() {
			b := bytes.NewReader([]byte{0x40, 0x10, 0x8e, 0x0, 0x1, 0x0})
			frame, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x10)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(0x10)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame, when packet 1 was lost", func() {
			b := bytes.NewReader([]byte{0x40, 0x9, 0x92, 0x7, 0x8, 0x3, 0x2, 0x69, 0xa3, 0x0, 0x0, 0x1, 0xc9, 0x2, 0x0, 0x46, 0x10})
			frame, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(9)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(2)))
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with multiple timestamps", func() {
			b := bytes.NewReader([]byte{0x40, 0x10, 0x0, 0x0, 0x10, 0x4, 0x1, 0x6b, 0x26, 0x4, 0x0, 0x3, 0, 0, 0x2, 0, 0, 0x1, 0, 0})
			_, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(BeZero())
		})

		It("errors when the ACK range is too large", func() {
			// LargestAcked: 0x1c
			// Length: 0x1d => LowestAcked would be -1
			b := bytes.NewReader([]byte{0x40, 0x1c, 0x8e, 0x0, 0x1d, 0x1, 0x1, 0x6b, 0x26, 0x3, 0x0})
			_, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).To(MatchError(ErrInvalidAckRanges))
		})

		It("errors when the first ACK range is empty", func() {
			b := bytes.NewReader([]byte{0x40, 0x9, 0x8e, 0x0, 0x0, 0x1, 0})
			_, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).To(MatchError(ErrInvalidFirstAckRange))
		})

		Context("ACK blocks", func() {
			It("parses a frame with one ACK block", func() {
				b := bytes.NewReader([]byte{0x60, 0x18, 0x94, 0x1, 0x1, 0x3, 0x2, 0x10, 0x2, 0x1, 0x5c, 0xd5, 0x0, 0x0, 0x0, 0x95, 0x0})
				frame, err := ParseAckFrame(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(24)))
				Expect(frame.HasMissingRanges()).To(BeTrue())
				Expect(frame.AckRanges).To(HaveLen(2))
				Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 22, LastPacketNumber: 24}))
				Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 4, LastPacketNumber: 19}))
				Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(4)))
				Expect(b.Len()).To(BeZero())
			})

			It("rejects a frame that says it has ACK blocks in the typeByte, but doesn't have any", func() {
				b := bytes.NewReader([]byte{0x63, 0x4, 0xff, 0xff, 0, 2, 0, 0, 0, 0, 0, 0})
				_, err := ParseAckFrame(b, protocol.VersionWhatever)
				Expect(err).To(MatchError(ErrInvalidAckRanges))
			})

			It("rejects a frame with invalid ACK ranges", func() {
				// like the test before, but increased the last ACK range, such that the FirstPacketNumber would be negative
				b := bytes.NewReader([]byte{0x60, 0x18, 0x94, 0x1, 0x1, 0x3, 0x2, 0x15, 0x2, 0x1, 0x5c, 0xd5, 0x0, 0x0, 0x0, 0x95, 0x0})
				_, err := ParseAckFrame(b, protocol.VersionWhatever)
				Expect(err).To(MatchError(ErrInvalidAckRanges))
			})

			It("parses a frame with multiple single packets missing", func() {
				b := bytes.NewReader([]byte{0x60, 0x27, 0xda, 0x0, 0x6, 0x9, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x13, 0x2, 0x1, 0x71, 0x12, 0x3, 0x0, 0x0, 0x47, 0x2})
				frame, err := ParseAckFrame(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x27)))
				Expect(frame.HasMissingRanges()).To(BeTrue())
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

			It("parses a packet with packet 1 and one more packet lost", func() {
				b := bytes.NewReader([]byte{0x60, 0xc, 0x92, 0x0, 0x1, 0x1, 0x1, 0x9, 0x2, 0x2, 0x53, 0x43, 0x1, 0x0, 0x0, 0xa7, 0x0})
				frame, err := ParseAckFrame(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(12)))
				Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(2)))
				Expect(frame.AckRanges).To(HaveLen(2))
				Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 12, LastPacketNumber: 12}))
				Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 2, LastPacketNumber: 10}))
				Expect(b.Len()).To(BeZero())
			})

			It("parses a frame with multiple longer ACK blocks", func() {
				b := bytes.NewReader([]byte{0x60, 0x52, 0xd1, 0x0, 0x3, 0x17, 0xa, 0x10, 0x4, 0x8, 0x2, 0x12, 0x2, 0x1, 0x6c, 0xc8, 0x2, 0x0, 0x0, 0x7e, 0x1})
				frame, err := ParseAckFrame(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x52)))
				Expect(frame.HasMissingRanges()).To(BeTrue())
				Expect(frame.AckRanges).To(HaveLen(4))
				Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 60, LastPacketNumber: 0x52}))
				Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 34, LastPacketNumber: 49}))
				Expect(frame.AckRanges[2]).To(Equal(AckRange{FirstPacketNumber: 22, LastPacketNumber: 29}))
				Expect(frame.AckRanges[3]).To(Equal(AckRange{FirstPacketNumber: 2, LastPacketNumber: 19}))
				Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(2)))
				Expect(b.Len()).To(BeZero())
			})

			Context("more than 256 lost packets in a row", func() {
				// 255 missing packets fit into a single ACK block
				It("parses a frame with a range of 255 missing packets", func() {
					b := bytes.NewReader([]byte{0x64, 0x15, 0x1, 0xce, 0x1, 0x1, 0x3, 0xff, 0x13, 0x1, 0x0, 0xb6, 0xc5, 0x0, 0x0})
					frame, err := ParseAckFrame(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x115)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 20 + 255, LastPacketNumber: 0x115}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 1, LastPacketNumber: 19}))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				// 256 missing packets fit into two ACK blocks
				It("parses a frame with a range of 256 missing packets", func() {
					b := bytes.NewReader([]byte{0x64, 0x14, 0x1, 0x96, 0x0, 0x2, 0x1, 0xff, 0x0, 0x1, 0x13, 0x1, 0x0, 0x92, 0xc0, 0x0, 0x0})
					frame, err := ParseAckFrame(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x114)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 20 + 256, LastPacketNumber: 0x114}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 1, LastPacketNumber: 19}))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with an incomplete range at the end", func() {
					// this is a modified ACK frame that has 5 instead of originally 6 written ranges
					// each gap is 300 packets and thus takes 2 ranges
					// the last range is incomplete, and should be completely ignored
					b := bytes.NewReader([]byte{0x64, 0x9b, 0x3, 0xc9, 0x0, 0x5 /*instead of 0x6*/, 0x1, 0xff, 0x0, 0x2d, 0x1, 0xff, 0x0, 0x2d, 0x1, 0xff, 0x0 /*0x2d, 0x14,*/, 0x1, 0x0, 0xf6, 0xbd, 0x0, 0x0})
					frame, err := ParseAckFrame(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x39b)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(3))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 20 + 3*301, LastPacketNumber: 20 + 3*301}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 20 + 2*301, LastPacketNumber: 20 + 2*301}))
					Expect(frame.AckRanges[2]).To(Equal(AckRange{FirstPacketNumber: 20 + 1*301, LastPacketNumber: 20 + 1*301}))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with one long range, spanning 2 blocks, of missing packets", func() { // 280 missing packets
					b := bytes.NewReader([]byte{0x64, 0x44, 0x1, 0xa7, 0x0, 0x2, 0x19, 0xff, 0x0, 0x19, 0x13, 0x2, 0x1, 0xb, 0x59, 0x2, 0x0, 0x0, 0xb6, 0x0})
					frame, err := ParseAckFrame(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x144)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 300, LastPacketNumber: 0x144}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 1, LastPacketNumber: 19}))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with one long range, spanning multiple blocks, of missing packets", func() { // 2345 missing packets
					b := bytes.NewReader([]byte{0x64, 0x5b, 0x9, 0x66, 0x1, 0xa, 0x1f, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0x32, 0x13, 0x4, 0x3, 0xb4, 0xda, 0x1, 0x0, 0x2, 0xe0, 0x0, 0x1, 0x9a, 0x0, 0x0, 0x81, 0x0})
					frame, err := ParseAckFrame(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x95b)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 2365, LastPacketNumber: 0x95b}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 1, LastPacketNumber: 19}))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with multiple long ranges of missing packets", func() {
					b := bytes.NewReader([]byte{0x65, 0x66, 0x9, 0x23, 0x1, 0x7, 0x7, 0x0, 0xff, 0x0, 0x0, 0xf5, 0x8a, 0x2, 0xc8, 0xe6, 0x0, 0xff, 0x0, 0x0, 0xff, 0x0, 0x0, 0xff, 0x0, 0x0, 0x23, 0x13, 0x0, 0x2, 0x1, 0x13, 0xae, 0xb, 0x0, 0x0, 0x80, 0x5})
					frame, err := ParseAckFrame(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x966)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(4))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 2400, LastPacketNumber: 0x966}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 1250, LastPacketNumber: 1899}))
					Expect(frame.AckRanges[2]).To(Equal(AckRange{FirstPacketNumber: 820, LastPacketNumber: 1049}))
					Expect(frame.AckRanges[3]).To(Equal(AckRange{FirstPacketNumber: 1, LastPacketNumber: 19}))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with short ranges and one long range", func() {
					b := bytes.NewReader([]byte{0x64, 0x8f, 0x3, 0x65, 0x1, 0x5, 0x3d, 0x1, 0x32, 0xff, 0x0, 0xff, 0x0, 0xf0, 0x1c, 0x2, 0x13, 0x3, 0x2, 0x23, 0xaf, 0x2, 0x0, 0x1, 0x3, 0x1, 0x0, 0x8e, 0x0})
					frame, err := ParseAckFrame(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x38f)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(4))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{FirstPacketNumber: 851, LastPacketNumber: 0x38f}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{FirstPacketNumber: 800, LastPacketNumber: 849}))
					Expect(frame.AckRanges[2]).To(Equal(AckRange{FirstPacketNumber: 22, LastPacketNumber: 49}))
					Expect(frame.AckRanges[3]).To(Equal(AckRange{FirstPacketNumber: 1, LastPacketNumber: 19}))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})
			})
		})

		It("errors on EOFs", func() {
			data := []byte{0x65, 0x66, 0x9, 0x23, 0x1, 0x7, 0x7, 0x0, 0xff, 0x0, 0x0, 0xf5, 0x8a, 0x2, 0xc8, 0xe6, 0x0, 0xff, 0x0, 0x0, 0xff, 0x0, 0x0, 0xff, 0x0, 0x0, 0x23, 0x13, 0x0, 0x2, 0x1, 0x13, 0xae, 0xb, 0x0, 0x0, 0x80, 0x5}
			_, err := ParseAckFrame(bytes.NewReader(data), protocol.VersionWhatever)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseAckFrame(bytes.NewReader(data[0:i]), protocol.VersionWhatever)
				Expect(err).To(MatchError("EOF"))
			}
		})
	})

	Context("when writing", func() {
		var b *bytes.Buffer

		BeforeEach(func() {
			b = &bytes.Buffer{}
		})

		Context("self-consistency", func() {
			It("writes a simple ACK frame", func() {
				frameOrig := &AckFrame{
					LargestAcked: 1,
					LowestAcked:  1,
				}
				err := frameOrig.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := ParseAckFrame(r, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(r.Len()).To(BeZero())
			})

			It("writes the correct block length in a simple ACK frame", func() {
				frameOrig := &AckFrame{
					LargestAcked: 20,
					LowestAcked:  10,
				}
				err := frameOrig.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := ParseAckFrame(r, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
				Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(r.Len()).To(BeZero())
			})

			It("writes a simple ACK frame with a high packet number", func() {
				frameOrig := &AckFrame{
					LargestAcked: 0xDEADBEEFCAFE,
					LowestAcked:  0xDEADBEEFCAFE,
				}
				err := frameOrig.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := ParseAckFrame(r, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(r.Len()).To(BeZero())
			})

			It("writes an ACK frame with one packet missing", func() {
				frameOrig := &AckFrame{
					LargestAcked: 40,
					LowestAcked:  1,
					AckRanges: []AckRange{
						{FirstPacketNumber: 25, LastPacketNumber: 40},
						{FirstPacketNumber: 1, LastPacketNumber: 23},
					},
				}
				err := frameOrig.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := ParseAckFrame(r, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
				Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
				Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				Expect(r.Len()).To(BeZero())
			})

			It("writes an ACK frame with multiple missing packets", func() {
				frameOrig := &AckFrame{
					LargestAcked: 25,
					LowestAcked:  1,
					AckRanges: []AckRange{
						{FirstPacketNumber: 22, LastPacketNumber: 25},
						{FirstPacketNumber: 15, LastPacketNumber: 18},
						{FirstPacketNumber: 13, LastPacketNumber: 13},
						{FirstPacketNumber: 1, LastPacketNumber: 10},
					},
				}
				err := frameOrig.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := ParseAckFrame(r, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
				Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
				Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				Expect(r.Len()).To(BeZero())
			})

			It("rejects a frame with incorrect LargestObserved value", func() {
				frame := &AckFrame{
					LargestAcked: 26,
					LowestAcked:  1,
					AckRanges: []AckRange{
						{FirstPacketNumber: 12, LastPacketNumber: 25},
						{FirstPacketNumber: 1, LastPacketNumber: 10},
					},
				}
				err := frame.Write(b, protocol.VersionWhatever)
				Expect(err).To(MatchError(errInconsistentAckLargestAcked))
			})

			It("rejects a frame with incorrect LargestObserved value", func() {
				frame := &AckFrame{
					LargestAcked: 25,
					LowestAcked:  2,
					AckRanges: []AckRange{
						{FirstPacketNumber: 12, LastPacketNumber: 25},
						{FirstPacketNumber: 1, LastPacketNumber: 10},
					},
				}
				err := frame.Write(b, protocol.VersionWhatever)
				Expect(err).To(MatchError(errInconsistentAckLowestAcked))
			})

			Context("longer gaps between ACK blocks", func() {
				It("only writes one block for 254 lost packets", func() {
					frameOrig := &AckFrame{
						LargestAcked: 300,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{FirstPacketNumber: 20 + 254, LastPacketNumber: 300},
							{FirstPacketNumber: 1, LastPacketNumber: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(2)))
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("only writes one block for 255 lost packets", func() {
					frameOrig := &AckFrame{
						LargestAcked: 300,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{FirstPacketNumber: 20 + 255, LastPacketNumber: 300},
							{FirstPacketNumber: 1, LastPacketNumber: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(2)))
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes two blocks for 256 lost packets", func() {
					frameOrig := &AckFrame{
						LargestAcked: 300,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{FirstPacketNumber: 20 + 256, LastPacketNumber: 300},
							{FirstPacketNumber: 1, LastPacketNumber: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(3)))
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					// Expect(b.Bytes()[13+0*(1+6) : 13+1*(1+6)]).To(Equal([]byte{0xFF, 0, 0, 0, 0, 0, 0}))
					// Expect(b.Bytes()[13+1*(1+6) : 13+2*(1+6)]).To(Equal([]byte{0x1, 0, 0, 0, 0, 0, 19}))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes two blocks for 510 lost packets", func() {
					frameOrig := &AckFrame{
						LargestAcked: 600,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{FirstPacketNumber: 20 + 510, LastPacketNumber: 600},
							{FirstPacketNumber: 1, LastPacketNumber: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(3)))
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes three blocks for 511 lost packets", func() {
					frameOrig := &AckFrame{
						LargestAcked: 600,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{FirstPacketNumber: 20 + 511, LastPacketNumber: 600},
							{FirstPacketNumber: 1, LastPacketNumber: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(4)))
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes three blocks for 512 lost packets", func() {
					frameOrig := &AckFrame{
						LargestAcked: 600,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{FirstPacketNumber: 20 + 512, LastPacketNumber: 600},
							{FirstPacketNumber: 1, LastPacketNumber: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(4)))
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes multiple blocks for a lot of lost packets", func() {
					frameOrig := &AckFrame{
						LargestAcked: 3000,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{FirstPacketNumber: 2900, LastPacketNumber: 3000},
							{FirstPacketNumber: 1, LastPacketNumber: 19},
						},
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes multiple longer blocks for 256 lost packets", func() {
					frameOrig := &AckFrame{
						LargestAcked: 3600,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{FirstPacketNumber: 2900, LastPacketNumber: 3600},
							{FirstPacketNumber: 1000, LastPacketNumber: 2500},
							{FirstPacketNumber: 1, LastPacketNumber: 19},
						},
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})
			})

			Context("longer ACK blocks", func() {
				It("writes a 1 byte Missing Sequence Number Delta", func() {
					frameOrig := &AckFrame{
						LargestAcked: 200,
						LowestAcked:  1,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x0)))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 2 byte Missing Sequence Number Delta", func() {
					frameOrig := &AckFrame{
						LargestAcked: 0x100,
						LowestAcked:  1,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x1)))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 4 byte Missing Sequence Number Delta", func() {
					frameOrig := &AckFrame{
						LargestAcked: 0x10000,
						LowestAcked:  1,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x2)))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 6 byte Missing Sequence Number Delta", func() {
					frameOrig := &AckFrame{
						LargestAcked: 0x100000000,
						LowestAcked:  1,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x3)))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 1 byte Missing Sequence Number Delta, if all ACK blocks are short", func() {
					frameOrig := &AckFrame{
						LargestAcked: 5001,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{FirstPacketNumber: 5000, LastPacketNumber: 5001},
							{FirstPacketNumber: 250, LastPacketNumber: 300},
							{FirstPacketNumber: 1, LastPacketNumber: 200},
						},
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x0)))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 2 byte Missing Sequence Number Delta, for a frame with 2 ACK ranges", func() {
					frameOrig := &AckFrame{
						LargestAcked: 10000,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{FirstPacketNumber: 9990, LastPacketNumber: 10000},
							{FirstPacketNumber: 1, LastPacketNumber: 256},
						},
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x1)))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
					Expect(r.Len()).To(BeZero())
				})
			})

			Context("too many ACK blocks", func() {
				It("skips the lowest ACK ranges, if there are more than 255 AckRanges", func() {
					ackRanges := make([]AckRange, 300)
					for i := 1; i <= 300; i++ {
						ackRanges[300-i] = AckRange{FirstPacketNumber: protocol.PacketNumber(3 * i), LastPacketNumber: protocol.PacketNumber(3*i + 1)}
					}
					frameOrig := &AckFrame{
						LargestAcked: ackRanges[0].LastPacketNumber,
						LowestAcked:  ackRanges[len(ackRanges)-1].FirstPacketNumber,
						AckRanges:    ackRanges,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(ackRanges[254].FirstPacketNumber))
					Expect(frame.AckRanges).To(HaveLen(0xFF))
					Expect(frame.validateAckRanges()).To(BeTrue())
				})

				It("skips the lowest ACK ranges, if the gaps are large", func() {
					ackRanges := make([]AckRange, 100)
					// every AckRange will take 4 written ACK ranges
					for i := 1; i <= 100; i++ {
						ackRanges[100-i] = AckRange{FirstPacketNumber: protocol.PacketNumber(1000 * i), LastPacketNumber: protocol.PacketNumber(1000*i + 1)}
					}
					frameOrig := &AckFrame{
						LargestAcked: ackRanges[0].LastPacketNumber,
						LowestAcked:  ackRanges[len(ackRanges)-1].FirstPacketNumber,
						AckRanges:    ackRanges,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(ackRanges[255/4].FirstPacketNumber))
					Expect(frame.validateAckRanges()).To(BeTrue())
				})

				It("works with huge gaps", func() {
					ackRanges := []AckRange{
						{FirstPacketNumber: 2 * 255 * 200, LastPacketNumber: 2*255*200 + 1},
						{FirstPacketNumber: 1 * 255 * 200, LastPacketNumber: 1*255*200 + 1},
						{FirstPacketNumber: 1, LastPacketNumber: 2},
					}
					frameOrig := &AckFrame{
						LargestAcked: ackRanges[0].LastPacketNumber,
						LowestAcked:  ackRanges[len(ackRanges)-1].FirstPacketNumber,
						AckRanges:    ackRanges,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.LowestAcked).To(Equal(ackRanges[1].FirstPacketNumber))
					Expect(frame.validateAckRanges()).To(BeTrue())
				})
			})
		})

		Context("min length", func() {
			It("has proper min length", func() {
				f := &AckFrame{
					LargestAcked: 1,
				}
				err := f.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has proper min length with a large LargestObserved", func() {
				f := &AckFrame{
					LargestAcked: 0xDEADBEEFCAFE,
				}
				err := f.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has the proper min length for an ACK with missing packets", func() {
				f := &AckFrame{
					LargestAcked: 2000,
					LowestAcked:  10,
					AckRanges: []AckRange{
						{FirstPacketNumber: 1000, LastPacketNumber: 2000},
						{FirstPacketNumber: 50, LastPacketNumber: 900},
						{FirstPacketNumber: 10, LastPacketNumber: 23},
					},
				}
				err := f.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has the proper min length for an ACK with long gaps of missing packets", func() {
				f := &AckFrame{
					LargestAcked: 2000,
					LowestAcked:  1,
					AckRanges: []AckRange{
						{FirstPacketNumber: 1500, LastPacketNumber: 2000},
						{FirstPacketNumber: 290, LastPacketNumber: 295},
						{FirstPacketNumber: 1, LastPacketNumber: 19},
					},
				}
				err := f.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has the proper min length for an ACK with a long ACK range", func() {
				largestAcked := protocol.PacketNumber(2 + 0xFFFFFF)
				f := &AckFrame{
					LargestAcked: largestAcked,
					LowestAcked:  1,
					AckRanges: []AckRange{
						{FirstPacketNumber: 1500, LastPacketNumber: largestAcked},
						{FirstPacketNumber: 290, LastPacketNumber: 295},
						{FirstPacketNumber: 1, LastPacketNumber: 19},
					},
				}
				err := f.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})
		})
	})

	Context("ACK range validator", func() {
		It("accepts an ACK without NACK Ranges", func() {
			ack := AckFrame{LargestAcked: 7}
			Expect(ack.validateAckRanges()).To(BeTrue())
		})

		It("rejects ACK ranges with a single range", func() {
			ack := AckFrame{
				LargestAcked: 10,
				AckRanges:    []AckRange{{FirstPacketNumber: 1, LastPacketNumber: 10}},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges with LastPacketNumber of the first range unequal to LargestObserved", func() {
			ack := AckFrame{
				LargestAcked: 10,
				AckRanges: []AckRange{
					{FirstPacketNumber: 8, LastPacketNumber: 9},
					{FirstPacketNumber: 2, LastPacketNumber: 3},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges with FirstPacketNumber greater than LastPacketNumber", func() {
			ack := AckFrame{
				LargestAcked: 10,
				AckRanges: []AckRange{
					{FirstPacketNumber: 8, LastPacketNumber: 10},
					{FirstPacketNumber: 4, LastPacketNumber: 3},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges with FirstPacketNumber greater than LargestObserved", func() {
			ack := AckFrame{
				LargestAcked: 5,
				AckRanges: []AckRange{
					{FirstPacketNumber: 4, LastPacketNumber: 10},
					{FirstPacketNumber: 1, LastPacketNumber: 2},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges in the wrong order", func() {
			ack := AckFrame{
				LargestAcked: 7,
				AckRanges: []AckRange{
					{FirstPacketNumber: 2, LastPacketNumber: 2},
					{FirstPacketNumber: 6, LastPacketNumber: 7},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects with overlapping ACK ranges", func() {
			ack := AckFrame{
				LargestAcked: 7,
				AckRanges: []AckRange{
					{FirstPacketNumber: 5, LastPacketNumber: 7},
					{FirstPacketNumber: 2, LastPacketNumber: 5},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges that are part of a larger ACK range", func() {
			ack := AckFrame{
				LargestAcked: 7,
				AckRanges: []AckRange{
					{FirstPacketNumber: 4, LastPacketNumber: 7},
					{FirstPacketNumber: 5, LastPacketNumber: 6},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects with directly adjacent ACK ranges", func() {
			ack := AckFrame{
				LargestAcked: 7,
				AckRanges: []AckRange{
					{FirstPacketNumber: 5, LastPacketNumber: 7},
					{FirstPacketNumber: 2, LastPacketNumber: 4},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("accepts an ACK with one lost packet", func() {
			ack := AckFrame{
				LargestAcked: 10,
				AckRanges: []AckRange{
					{FirstPacketNumber: 5, LastPacketNumber: 10},
					{FirstPacketNumber: 1, LastPacketNumber: 3},
				},
			}
			Expect(ack.validateAckRanges()).To(BeTrue())
		})

		It("accepts an ACK with multiple lost packets", func() {
			ack := AckFrame{
				LargestAcked: 20,
				AckRanges: []AckRange{
					{FirstPacketNumber: 15, LastPacketNumber: 20},
					{FirstPacketNumber: 10, LastPacketNumber: 12},
					{FirstPacketNumber: 1, LastPacketNumber: 3},
				},
			}
			Expect(ack.validateAckRanges()).To(BeTrue())
		})
	})

	Context("check if ACK frame acks a certain packet", func() {
		It("works with an ACK without any ranges", func() {
			f := AckFrame{
				LowestAcked:  5,
				LargestAcked: 10,
			}
			Expect(f.AcksPacket(1)).To(BeFalse())
			Expect(f.AcksPacket(4)).To(BeFalse())
			Expect(f.AcksPacket(5)).To(BeTrue())
			Expect(f.AcksPacket(8)).To(BeTrue())
			Expect(f.AcksPacket(10)).To(BeTrue())
			Expect(f.AcksPacket(11)).To(BeFalse())
			Expect(f.AcksPacket(20)).To(BeFalse())
		})

		It("works with an ACK with multiple ACK ranges", func() {
			f := AckFrame{
				LowestAcked:  5,
				LargestAcked: 20,
				AckRanges: []AckRange{
					{FirstPacketNumber: 15, LastPacketNumber: 20},
					{FirstPacketNumber: 5, LastPacketNumber: 8},
				},
			}
			Expect(f.AcksPacket(4)).To(BeFalse())
			Expect(f.AcksPacket(5)).To(BeTrue())
			Expect(f.AcksPacket(7)).To(BeTrue())
			Expect(f.AcksPacket(8)).To(BeTrue())
			Expect(f.AcksPacket(9)).To(BeFalse())
			Expect(f.AcksPacket(14)).To(BeFalse())
			Expect(f.AcksPacket(15)).To(BeTrue())
			Expect(f.AcksPacket(18)).To(BeTrue())
			Expect(f.AcksPacket(20)).To(BeTrue())
			Expect(f.AcksPacket(21)).To(BeFalse())
		})
	})
})
