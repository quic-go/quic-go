package wire

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AckFrame", func() {
	Context("when parsing", func() {
		It("accepts a sample frame", func() {
			b := bytes.NewReader([]byte{0x40,
				0x1c,     // largest acked
				0x0, 0x0, // delay time
				0x1c, // block length
				0,
			})
			frame, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x1c)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame where the largest acked is 0", func() {
			b := bytes.NewReader([]byte{0x40,
				0x0,      // largest acked
				0x0, 0x0, // delay time
				0x0, // block length
				0,
			})
			frame, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(0)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with 1 ACKed packet", func() {
			b := bytes.NewReader([]byte{0x40,
				0x10,     // largest acked
				0x0, 0x0, // delay time
				0x1, // block length
				0,
			})
			frame, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x10)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(0x10)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with multiple timestamps", func() {
			b := bytes.NewReader([]byte{0x40,
				0x10,     // largest acked
				0x0, 0x0, // timestamp
				0x10,                      // block length
				0x4,                       // num timestamps
				0x1, 0x6b, 0x26, 0x4, 0x0, // 1st timestamp
				0x3, 0, 0, // 2nd timestamp
				0x2, 0, 0, // 3rd timestamp
				0x1, 0, 0, // 4th timestamp
			})
			_, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(BeZero())
		})

		It("errors when the ACK range is too large", func() {
			// LargestAcked: 0x1c
			// Length: 0x1d => LowestAcked would be -1
			b := bytes.NewReader([]byte{0x40,
				0x1c,     // largest acked
				0x0, 0x0, // delay time
				0x1d, // block length
				0,
			})
			_, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).To(MatchError(ErrInvalidAckRanges))
		})

		It("errors when the first ACK range is empty", func() {
			b := bytes.NewReader([]byte{0x40,
				0x9,      // largest acked
				0x0, 0x0, // delay time
				0x0, // block length
				0,
			})
			_, err := ParseAckFrame(b, protocol.VersionWhatever)
			Expect(err).To(MatchError(ErrInvalidFirstAckRange))
		})

		Context("in little endian", func() {
			It("parses the delay time", func() {
				b := bytes.NewReader([]byte{0x40,
					0x3,       // largest acked
					0x8e, 0x0, // delay time
					0x3, // block length
					0,
				})
				frame, err := ParseAckFrame(b, versionLittleEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(frame.DelayTime).To(Equal(142 * time.Microsecond))
			})

			It("errors on EOFs", func() {
				data := []byte{0x60 ^ 0x4 ^ 0x1,
					0x66, 0x9, // largest acked
					0x23, 0x1, // delay time
					0x7,      // num ACk blocks
					0x7, 0x0, // 1st block
					0xff, 0x0, 0x0, // 2nd block
					0xf5, 0x8a, 0x2, // 3rd block
					0xc8, 0xe6, 0x0, // 4th block
					0xff, 0x0, 0x0, // 5th block
					0xff, 0x0, 0x0, // 6th block
					0xff, 0x0, 0x0, // 7th block
					0x23, 0x13, 0x0, // 8th blocks
					0x2,                       // num timestamps
					0x1, 0x13, 0xae, 0xb, 0x0, // 1st timestamp
					0x0, 0x80, 0x5, // 2nd timestamp
				}
				_, err := ParseAckFrame(bytes.NewReader(data), versionLittleEndian)
				Expect(err).NotTo(HaveOccurred())
				for i := range data {
					_, err := ParseAckFrame(bytes.NewReader(data[0:i]), versionLittleEndian)
					Expect(err).To(MatchError(io.EOF))
				}
			})

			Context("largest acked length", func() {
				It("parses a frame with a 2 byte packet number", func() {
					b := bytes.NewReader([]byte{0x40 | 0x4,
						0x37, 0x13, // largest acked
						0x0, 0x0, // delay time
						0x9, // block length
						0,
					})
					frame, err := ParseAckFrame(b, versionLittleEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x1337)))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(0x1337 - 0x9 + 1)))
					Expect(frame.HasMissingRanges()).To(BeFalse())
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with a 4 byte packet number", func() {
					b := bytes.NewReader([]byte{0x40 | 0x8,
						0xad, 0xfb, 0xca, 0xde, // largest acked
						0x0, 0x0, // timesatmp
						0x5, // block length
						0,
					})
					frame, err := ParseAckFrame(b, versionLittleEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0xdecafbad)))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(0xdecafbad - 5 + 1)))
					Expect(frame.HasMissingRanges()).To(BeFalse())
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with a 6 byte packet number", func() {
					b := bytes.NewReader([]byte{0x4 | 0xc,
						0x37, 0x13, 0xad, 0xfb, 0xca, 0xde, // largest acked
						0x0, 0x0, // delay time
						0x5, // block length
						0,
					})
					frame, err := ParseAckFrame(b, versionLittleEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0xdecafbad1337)))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(0xdecafbad1337 - 5 + 1)))
					Expect(frame.HasMissingRanges()).To(BeFalse())
					Expect(b.Len()).To(BeZero())
				})
			})
		})

		Context("in big endian", func() {
			It("parses the delay time", func() {
				b := bytes.NewReader([]byte{0x40,
					0x3,       // largest acked
					0x0, 0x8e, // delay time
					0x3, // block length
					0,
				})
				frame, err := ParseAckFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(frame.DelayTime).To(Equal(142 * time.Microsecond))
			})

			It("errors on EOFs", func() {
				data := []byte{0x60 ^ 0x4 ^ 0x1,
					0x9, 0x66, // largest acked
					0x23, 0x1, // delay time
					0x7,      // num ACk blocks
					0x0, 0x7, // 1st block
					0xff, 0x0, 0x0, // 2nd block
					0xf5, 0x2, 0x8a, // 3rd block
					0xc8, 0x0, 0xe6, // 4th block
					0xff, 0x0, 0x0, // 5th block
					0xff, 0x0, 0x0, // 6th block
					0xff, 0x0, 0x0, // 7th block
					0x23, 0x0, 0x13, // 8th blocks
					0x2,                       // num timestamps
					0x1, 0x13, 0xae, 0xb, 0x0, // 1st timestamp
					0x0, 0x80, 0x5, // 2nd timestamp
				}
				_, err := ParseAckFrame(bytes.NewReader(data), versionBigEndian)
				Expect(err).NotTo(HaveOccurred())
				for i := range data {
					_, err := ParseAckFrame(bytes.NewReader(data[0:i]), versionBigEndian)
					Expect(err).To(MatchError(io.EOF))
				}
			})

			Context("largest acked length", func() {
				It("parses a frame with a 2 byte packet number", func() {
					b := bytes.NewReader([]byte{0x40 | 0x4,
						0x13, 0x37, // largest acked
						0x0, 0x0, // delay time
						0x9, // block length
						0,
					})
					frame, err := ParseAckFrame(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x1337)))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(0x1337 - 0x9 + 1)))
					Expect(frame.HasMissingRanges()).To(BeFalse())
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with a 4 byte packet number", func() {
					b := bytes.NewReader([]byte{0x40 | 0x8,
						0xde, 0xca, 0xfb, 0xad, // largest acked
						0x0, 0x0, // timesatmp
						0x5, // block length
						0,
					})
					frame, err := ParseAckFrame(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0xdecafbad)))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(0xdecafbad - 5 + 1)))
					Expect(frame.HasMissingRanges()).To(BeFalse())
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with a 6 byte packet number", func() {
					b := bytes.NewReader([]byte{0x4 | 0xc,
						0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // largest acked
						0x0, 0x0, // delay time
						0x5, // block length
						0,
					})
					frame, err := ParseAckFrame(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0xdeadbeefcafe)))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(0xdeadbeefcafe - 5 + 1)))
					Expect(frame.HasMissingRanges()).To(BeFalse())
					Expect(b.Len()).To(BeZero())
				})
			})
		})

		Context("ACK blocks", func() {
			It("parses a frame with two ACK blocks", func() {
				b := bytes.NewReader([]byte{0x60,
					0x18,     // largest acked
					0x0, 0x0, // delay time
					0x1,       // num ACK blocks
					0x3,       // 1st block
					0x2, 0x10, // 2nd block
					0,
				})
				frame, err := ParseAckFrame(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x18)))
				Expect(frame.HasMissingRanges()).To(BeTrue())
				Expect(frame.AckRanges).To(HaveLen(2))
				Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 0x18 - 0x3 + 1, Last: 0x18}))
				Expect(frame.AckRanges[1]).To(Equal(AckRange{First: (0x18 - 0x3 + 1) - (0x2 + 1) - (0x10 - 1), Last: (0x18 - 0x3 + 1) - (0x2 + 1)}))
				Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(4)))
				Expect(b.Len()).To(BeZero())
			})

			It("rejects a frame with invalid ACK ranges", func() {
				// like the test before, but increased the last ACK range, such that the First would be negative
				b := bytes.NewReader([]byte{0x60,
					0x18,     // largest acked
					0x0, 0x0, // delay time
					0x1,       // num ACK blocks
					0x3,       // 1st block
					0x2, 0x15, // 2nd block
					0,
				})
				_, err := ParseAckFrame(b, protocol.VersionWhatever)
				Expect(err).To(MatchError(ErrInvalidAckRanges))
			})

			It("rejects a frame that says it has ACK blocks in the typeByte, but doesn't have any", func() {
				b := bytes.NewReader([]byte{0x60 ^ 0x3,
					0x4,      // largest acked
					0x0, 0x0, // delay time
					0, // num ACK blocks
					0,
				})
				_, err := ParseAckFrame(b, protocol.VersionWhatever)
				Expect(err).To(MatchError(ErrInvalidAckRanges))
			})

			It("parses a frame with multiple single packets missing", func() {
				b := bytes.NewReader([]byte{0x60,
					0x27,     // largest acked
					0x0, 0x0, // delay time
					0x6,      // num ACK blocks
					0x9,      // 1st block
					0x1, 0x1, // 2nd block
					0x1, 0x1, // 3rd block
					0x1, 0x1, // 4th block
					0x1, 0x1, // 5th block
					0x1, 0x1, // 6th block
					0x1, 0x13, // 7th block
					0,
				})
				frame, err := ParseAckFrame(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x27)))
				Expect(frame.HasMissingRanges()).To(BeTrue())
				Expect(frame.AckRanges).To(HaveLen(7))
				Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 31, Last: 0x27}))
				Expect(frame.AckRanges[1]).To(Equal(AckRange{First: 29, Last: 29}))
				Expect(frame.AckRanges[2]).To(Equal(AckRange{First: 27, Last: 27}))
				Expect(frame.AckRanges[3]).To(Equal(AckRange{First: 25, Last: 25}))
				Expect(frame.AckRanges[4]).To(Equal(AckRange{First: 23, Last: 23}))
				Expect(frame.AckRanges[5]).To(Equal(AckRange{First: 21, Last: 21}))
				Expect(frame.AckRanges[6]).To(Equal(AckRange{First: 1, Last: 19}))
				Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
				Expect(b.Len()).To(BeZero())
			})

			It("parses a frame with multiple longer ACK blocks", func() {
				b := bytes.NewReader([]byte{0x60,
					0x52,      // largest acked
					0xd1, 0x0, //delay time
					0x3,       // num ACK blocks
					0x17,      // 1st block
					0xa, 0x10, // 2nd block
					0x4, 0x8, // 3rd block
					0x2, 0x12, // 4th block
					0,
				})
				frame, err := ParseAckFrame(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x52)))
				Expect(frame.HasMissingRanges()).To(BeTrue())
				Expect(frame.AckRanges).To(HaveLen(4))
				Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 60, Last: 0x52}))
				Expect(frame.AckRanges[1]).To(Equal(AckRange{First: 34, Last: 49}))
				Expect(frame.AckRanges[2]).To(Equal(AckRange{First: 22, Last: 29}))
				Expect(frame.AckRanges[3]).To(Equal(AckRange{First: 2, Last: 19}))
				Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(2)))
				Expect(b.Len()).To(BeZero())
			})

			Context("more than 256 lost packets in a row", func() {
				// 255 missing packets fit into a single ACK block
				It("parses a frame with a range of 255 missing packets", func() {
					b := bytes.NewReader([]byte{0x60 ^ 0x4,
						0x15, 0x1, // largest acked
						0x0, 0x0, // delay time
						0x1,        // num ACK blocks
						0x3,        // 1st block
						0xff, 0x13, // 2nd block
						0,
					})
					frame, err := ParseAckFrame(b, versionLittleEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x115)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 20 + 255, Last: 0x115}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{First: 1, Last: 19}))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				// 256 missing packets fit into two ACK blocks
				It("parses a frame with a range of 256 missing packets", func() {
					b := bytes.NewReader([]byte{0x60 ^ 0x4,
						0x14, 0x1, // largest acked
						0x0, 0x0, // delay time
						0x2,       // num ACK blocks
						0x1,       // 1st block
						0xff, 0x0, // 2nd block
						0x1, 0x13, // 3rd block
						0,
					})
					frame, err := ParseAckFrame(b, versionLittleEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x114)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 20 + 256, Last: 0x114}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{First: 1, Last: 19}))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with an incomplete range at the end", func() {
					// this is a modified ACK frame that has 5 instead of originally 6 written ranges
					// each gap is 300 packets and thus takes 2 ranges
					// the last range is incomplete, and should be completely ignored
					b := bytes.NewReader([]byte{0x60 ^ 0x4,
						0x9b, 0x3, // largest acked
						0x0, 0x0, // delay time
						0x5,       // num ACK blocks, instead of 0x6
						0x1,       // 1st block
						0xff, 0x0, // 2nd block
						0x2d, 0x1, // 3rd block
						0xff, 0x0, // 4th block
						0x2d, 0x1, // 5th block
						0xff, 0x0, /*0x2d, 0x14,*/ // 6th block
						0,
					})
					frame, err := ParseAckFrame(b, versionLittleEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x39b)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(3))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 20 + 3*301, Last: 20 + 3*301}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{First: 20 + 2*301, Last: 20 + 2*301}))
					Expect(frame.AckRanges[2]).To(Equal(AckRange{First: 20 + 1*301, Last: 20 + 1*301}))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with one long range, spanning 2 blocks, of missing packets", func() {
					// 280 missing packets
					b := bytes.NewReader([]byte{0x60 ^ 0x4,
						0x44, 0x1, // largest acked
						0x0, 0x0, // delay time
						0x2,       // num ACK blocks
						0x19,      // 1st block
						0xff, 0x0, // 2nd block
						0x19, 0x13, // 3rd block
						0,
					})
					frame, err := ParseAckFrame(b, versionLittleEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x144)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 300, Last: 0x144}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{First: 1, Last: 19}))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with one long range, spanning multiple blocks, of missing packets", func() {
					// 2345 missing packets
					b := bytes.NewReader([]byte{0x60 ^ 0x4,
						0x5b, 0x9, // largest acked
						0x0, 0x0, // delay time
						0xa,       // num ACK blocks
						0x1f,      // 1st block
						0xff, 0x0, // 2nd block
						0xff, 0x0, // 3rd block
						0xff, 0x0, // 4th block
						0xff, 0x0, // 5th block
						0xff, 0x0, // 6th block
						0xff, 0x0, // 7th block
						0xff, 0x0, // 8th block
						0xff, 0x0, // 9th block
						0xff, 0x0, // 10th block
						0x32, 0x13, // 11th block
						0,
					})
					frame, err := ParseAckFrame(b, versionLittleEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x95b)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 2365, Last: 0x95b}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{First: 1, Last: 19}))
					Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				Context("in little endian", func() {
					It("parses a frame with multiple 2 byte long ranges of missing packets", func() {
						b := bytes.NewReader([]byte{0x60 ^ 0x4 ^ 0x1,
							0x66, 0x9, // largest acked
							0x0, 0x0, // delay time
							0x7,      // num ACK blocks
							0x7, 0x0, // 1st block
							0xff, 0x0, 0x0, // 2nd block
							0xf5, 0x8a, 0x2, // 3rd block
							0xc8, 0xe6, 0x0, // 4th block
							0xff, 0x0, 0x0, // 5th block
							0xff, 0x0, 0x0, // 6th block
							0xff, 0x0, 0x0, // 7th block
							0x23, 0x13, 0x0, // 8th block
							0,
						})
						frame, err := ParseAckFrame(b, versionLittleEndian)
						Expect(err).ToNot(HaveOccurred())
						Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x966)))
						Expect(frame.HasMissingRanges()).To(BeTrue())
						Expect(frame.AckRanges).To(HaveLen(4))
						Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 2400, Last: 0x966}))
						Expect(frame.AckRanges[1]).To(Equal(AckRange{First: 1250, Last: 1899}))
						Expect(frame.AckRanges[2]).To(Equal(AckRange{First: 820, Last: 1049}))
						Expect(frame.AckRanges[3]).To(Equal(AckRange{First: 1, Last: 19}))
						Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
						Expect(b.Len()).To(BeZero())
					})

					It("parses a frame with with a 4 byte ack block length", func() {
						b := bytes.NewReader([]byte{0x60 ^ 0xc ^ 0x2,
							0xfe, 0xca, 0xef, 0xbe, 0xad, 0xde, // largest acked
							0x0, 0x0, // delay time
							0x1,              // num ACK blocks
							0x37, 0x13, 0, 0, // 1st block
							0x20, 0x78, 0x56, 0x34, 0x12, // 2nd block
							0,
						})
						frame, err := ParseAckFrame(b, versionLittleEndian)
						Expect(err).ToNot(HaveOccurred())
						Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0xdeadbeefcafe)))
						Expect(frame.HasMissingRanges()).To(BeTrue())
						Expect(frame.AckRanges).To(HaveLen(2))
						Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 0xdeadbeefcafe - 0x1337 + 1, Last: 0xdeadbeefcafe}))
						Expect(frame.AckRanges[1]).To(Equal(AckRange{First: (0xdeadbeefcafe - 0x1337 + 1) - (0x20 + 1) - (0x12345678 - 1), Last: (0xdeadbeefcafe - 0x1337 + 1) - (0x20 + 1)}))
					})

					It("parses a frame with with a 6 byte ack block length", func() {
						b := bytes.NewReader([]byte{0x60 ^ 0xc ^ 0x3,
							0xfe, 0xca, 0xef, 0xbe, 0xad, 0xde, // largest acked
							0x0, 0x0, // delay time
							0x1,                    // num ACk blocks
							0x37, 0x13, 0, 0, 0, 0, // 1st block
							0x20, 0x78, 0x56, 0x34, 0x12, 0xab, 0, // 2nd block
							0,
						})
						frame, err := ParseAckFrame(b, versionLittleEndian)
						Expect(err).ToNot(HaveOccurred())
						Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0xdeadbeefcafe)))
						Expect(frame.HasMissingRanges()).To(BeTrue())
						Expect(frame.AckRanges).To(HaveLen(2))
						Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 0xdeadbeefcafe - 0x1337 + 1, Last: 0xdeadbeefcafe}))
						Expect(frame.AckRanges[1]).To(Equal(AckRange{First: (0xdeadbeefcafe - 0x1337 + 1) - (0x20 + 1) - (0xab12345678 - 1), Last: (0xdeadbeefcafe - 0x1337 + 1) - (0x20 + 1)}))
					})
				})

				Context("in big endian", func() {
					It("parses a frame with multiple 2 byte long ranges of missing packets", func() {
						b := bytes.NewReader([]byte{0x60 ^ 0x4 ^ 0x1,
							0x9, 0x66, // largest acked
							0x0, 0x0, // delay time
							0x7,      // num ACK blocks
							0x0, 0x7, // 1st block
							0xff, 0x0, 0x0, // 2nd block
							0xf5, 0x2, 0x8a, // 3rd block
							0xc8, 0x0, 0xe6, // 4th block
							0xff, 0x0, 0x0, // 5th block
							0xff, 0x0, 0x0, // 6th block
							0xff, 0x0, 0x0, // 7th block
							0x23, 0x0, 0x13, // 8th block
							0,
						})
						frame, err := ParseAckFrame(b, versionBigEndian)
						Expect(err).ToNot(HaveOccurred())
						Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0x966)))
						Expect(frame.HasMissingRanges()).To(BeTrue())
						Expect(frame.AckRanges).To(HaveLen(4))
						Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 2400, Last: 0x966}))
						Expect(frame.AckRanges[1]).To(Equal(AckRange{First: 1250, Last: 1899}))
						Expect(frame.AckRanges[2]).To(Equal(AckRange{First: 820, Last: 1049}))
						Expect(frame.AckRanges[3]).To(Equal(AckRange{First: 1, Last: 19}))
						Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(1)))
						Expect(b.Len()).To(BeZero())
					})

					It("parses a frame with with a 4 byte ack block length", func() {
						b := bytes.NewReader([]byte{0x60 ^ 0xc ^ 0x2,
							0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // largest acked
							0x0, 0x0, // delay time
							0x1,              // num ACK blocks
							0, 0, 0x13, 0x37, // 1st block
							0x20, 0x12, 0x34, 0x56, 0x78, // 2nd block
							0,
						})
						frame, err := ParseAckFrame(b, versionBigEndian)
						Expect(err).ToNot(HaveOccurred())
						Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0xdeadbeefcafe)))
						Expect(frame.HasMissingRanges()).To(BeTrue())
						Expect(frame.AckRanges).To(HaveLen(2))
						Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 0xdeadbeefcafe - 0x1337 + 1, Last: 0xdeadbeefcafe}))
						Expect(frame.AckRanges[1]).To(Equal(AckRange{First: (0xdeadbeefcafe - 0x1337 + 1) - (0x20 + 1) - (0x12345678 - 1), Last: (0xdeadbeefcafe - 0x1337 + 1) - (0x20 + 1)}))
					})

					It("parses a frame with with a 6 byte ack block length", func() {
						b := bytes.NewReader([]byte{0x60 ^ 0xc ^ 0x3,
							0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // largest acked
							0x0, 0x0, // delay time
							0x1,                    // num ACk blocks
							0, 0, 0, 0, 0x13, 0x37, // 1st block
							0x20, 0x0, 0xab, 0x12, 0x34, 0x56, 0x78, // 2nd block
							0,
						})
						frame, err := ParseAckFrame(b, versionBigEndian)
						Expect(err).ToNot(HaveOccurred())
						Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(0xdeadbeefcafe)))
						Expect(frame.HasMissingRanges()).To(BeTrue())
						Expect(frame.AckRanges).To(HaveLen(2))
						Expect(frame.AckRanges[0]).To(Equal(AckRange{First: 0xdeadbeefcafe - 0x1337 + 1, Last: 0xdeadbeefcafe}))
						Expect(frame.AckRanges[1]).To(Equal(AckRange{First: (0xdeadbeefcafe - 0x1337 + 1) - (0x20 + 1) - (0xab12345678 - 1), Last: (0xdeadbeefcafe - 0x1337 + 1) - (0x20 + 1)}))
					})
				})
			})
		})
	})

	Context("when writing", func() {
		var b *bytes.Buffer

		BeforeEach(func() {
			b = &bytes.Buffer{}
		})

		Context("self-consistency", func() {
			for _, v := range []protocol.VersionNumber{versionLittleEndian, versionBigEndian} {
				version := v
				name := "little endian"
				if version == versionBigEndian {
					name = "big endian"
				}

				Context(fmt.Sprintf("in %s", name), func() {
					It("writes a simple ACK frame", func() {
						frameOrig := &AckFrame{
							LargestAcked: 1,
							LowestAcked:  1,
						}
						err := frameOrig.Write(b, version)
						Expect(err).ToNot(HaveOccurred())
						r := bytes.NewReader(b.Bytes())
						frame, err := ParseAckFrame(r, version)
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
						err := frameOrig.Write(b, version)
						Expect(err).ToNot(HaveOccurred())
						r := bytes.NewReader(b.Bytes())
						frame, err := ParseAckFrame(r, version)
						Expect(err).ToNot(HaveOccurred())
						Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
						Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
						Expect(frame.HasMissingRanges()).To(BeFalse())
						Expect(r.Len()).To(BeZero())
					})

					It("writes a simple ACK frame with a high packet number", func() {
						frameOrig := &AckFrame{
							LargestAcked: 0xdeadbeefcafe,
							LowestAcked:  0xdeadbeefcafe,
						}
						err := frameOrig.Write(b, version)
						Expect(err).ToNot(HaveOccurred())
						r := bytes.NewReader(b.Bytes())
						frame, err := ParseAckFrame(r, version)
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
								{First: 25, Last: 40},
								{First: 1, Last: 23},
							},
						}
						err := frameOrig.Write(b, version)
						Expect(err).ToNot(HaveOccurred())
						r := bytes.NewReader(b.Bytes())
						frame, err := ParseAckFrame(r, version)
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
								{First: 22, Last: 25},
								{First: 15, Last: 18},
								{First: 13, Last: 13},
								{First: 1, Last: 10},
							},
						}
						err := frameOrig.Write(b, version)
						Expect(err).ToNot(HaveOccurred())
						r := bytes.NewReader(b.Bytes())
						frame, err := ParseAckFrame(r, version)
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
								{First: 12, Last: 25},
								{First: 1, Last: 10},
							},
						}
						err := frame.Write(b, version)
						Expect(err).To(MatchError(errInconsistentAckLargestAcked))
					})

					It("rejects a frame with incorrect LargestObserved value", func() {
						frame := &AckFrame{
							LargestAcked: 25,
							LowestAcked:  2,
							AckRanges: []AckRange{
								{First: 12, Last: 25},
								{First: 1, Last: 10},
							},
						}
						err := frame.Write(b, version)
						Expect(err).To(MatchError(errInconsistentAckLowestAcked))
					})

					Context("longer gaps between ACK blocks", func() {
						It("only writes one block for 254 lost packets", func() {
							frameOrig := &AckFrame{
								LargestAcked: 300,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 20 + 254, Last: 300},
									{First: 1, Last: 19},
								},
							}
							Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(2)))
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
						})

						It("only writes one block for 255 lost packets", func() {
							frameOrig := &AckFrame{
								LargestAcked: 300,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 20 + 255, Last: 300},
									{First: 1, Last: 19},
								},
							}
							Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(2)))
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
						})

						It("writes two blocks for 256 lost packets", func() {
							frameOrig := &AckFrame{
								LargestAcked: 300,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 20 + 256, Last: 300},
									{First: 1, Last: 19},
								},
							}
							Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(3)))
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
						})

						It("writes two blocks for 510 lost packets", func() {
							frameOrig := &AckFrame{
								LargestAcked: 600,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 20 + 510, Last: 600},
									{First: 1, Last: 19},
								},
							}
							Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(3)))
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
						})

						It("writes three blocks for 511 lost packets", func() {
							frameOrig := &AckFrame{
								LargestAcked: 600,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 20 + 511, Last: 600},
									{First: 1, Last: 19},
								},
							}
							Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(4)))
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
						})

						It("writes three blocks for 512 lost packets", func() {
							frameOrig := &AckFrame{
								LargestAcked: 600,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 20 + 512, Last: 600},
									{First: 1, Last: 19},
								},
							}
							Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(4)))
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
						})

						It("writes multiple blocks for a lot of lost packets", func() {
							frameOrig := &AckFrame{
								LargestAcked: 3000,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 2900, Last: 3000},
									{First: 1, Last: 19},
								},
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
						})

						It("writes multiple longer blocks for 256 lost packets", func() {
							frameOrig := &AckFrame{
								LargestAcked: 3600,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 2900, Last: 3600},
									{First: 1000, Last: 2500},
									{First: 1, Last: 19},
								},
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
						})
					})

					Context("largest acked length", func() {
						It("writes a 1 largest acked", func() {
							frameOrig := &AckFrame{
								LargestAcked: 200,
								LowestAcked:  1,
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x0)))
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
							Expect(r.Len()).To(BeZero())
						})

						It("writes a 2 byte largest acked", func() {
							frameOrig := &AckFrame{
								LargestAcked: 0x100,
								LowestAcked:  1,
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x1)))
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
							Expect(r.Len()).To(BeZero())
						})

						It("writes a 4 byte largest acked", func() {
							frameOrig := &AckFrame{
								LargestAcked: 0x10000,
								LowestAcked:  1,
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x2)))
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
							Expect(r.Len()).To(BeZero())
						})

						It("writes a 6 byte largest acked", func() {
							frameOrig := &AckFrame{
								LargestAcked: 0x100000000,
								LowestAcked:  1,
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x3)))
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
							Expect(r.Len()).To(BeZero())
						})
					})

					Context("ack block length", func() {
						It("writes a 1 byte ack block length, if all ACK blocks are short", func() {
							frameOrig := &AckFrame{
								LargestAcked: 5001,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 5000, Last: 5001},
									{First: 250, Last: 300},
									{First: 1, Last: 200},
								},
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x0)))
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
							Expect(r.Len()).To(BeZero())
						})

						It("writes a 2 byte ack block length, for a frame with one ACK block", func() {
							frameOrig := &AckFrame{
								LargestAcked: 10000,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 9990, Last: 10000},
									{First: 1, Last: 9988},
								},
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x1)))
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
							Expect(r.Len()).To(BeZero())
						})

						It("writes a 2 byte ack block length, for a frame with multiple ACK blocks", func() {
							frameOrig := &AckFrame{
								LargestAcked: 10000,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 9990, Last: 10000},
									{First: 1, Last: 256},
								},
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x1)))
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
							Expect(r.Len()).To(BeZero())
						})

						It("writes a 4 byte ack block length, for a frame with single ACK blocks", func() {
							frameOrig := &AckFrame{
								LargestAcked: 0xdeadbeef,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 9990, Last: 0xdeadbeef},
									{First: 1, Last: 9988},
								},
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x2)))
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
							Expect(r.Len()).To(BeZero())
						})

						It("writes a 4 byte ack block length, for a frame with multiple ACK blocks", func() {
							frameOrig := &AckFrame{
								LargestAcked: 0xdeadbeef,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 9990, Last: 0xdeadbeef},
									{First: 1, Last: 256},
								},
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x2)))
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
							Expect(r.Len()).To(BeZero())
						})

						It("writes a 6 byte ack block length, for a frame with a single ACK blocks", func() {
							frameOrig := &AckFrame{
								LargestAcked: 0xdeadbeefcafe,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 9990, Last: 0xdeadbeefcafe},
									{First: 1, Last: 9988},
								},
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x3)))
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
							Expect(r.Len()).To(BeZero())
						})

						It("writes a 6 byte ack block length, for a frame with multiple ACK blocks", func() {
							frameOrig := &AckFrame{
								LargestAcked: 0xdeadbeefcafe,
								LowestAcked:  1,
								AckRanges: []AckRange{
									{First: 9990, Last: 0xdeadbeefcafe},
									{First: 1, Last: 256},
								},
							}
							err := frameOrig.Write(b, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x3)))
							r := bytes.NewReader(b.Bytes())
							frame, err := ParseAckFrame(r, version)
							Expect(err).ToNot(HaveOccurred())
							Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
							Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
							Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
							Expect(r.Len()).To(BeZero())
						})
					})
				})
			}

			Context("too many ACK blocks", func() {
				It("skips the lowest ACK ranges, if there are more than 255 AckRanges", func() {
					ackRanges := make([]AckRange, 300)
					for i := 1; i <= 300; i++ {
						ackRanges[300-i] = AckRange{First: protocol.PacketNumber(3 * i), Last: protocol.PacketNumber(3*i + 1)}
					}
					frameOrig := &AckFrame{
						LargestAcked: ackRanges[0].Last,
						LowestAcked:  ackRanges[len(ackRanges)-1].First,
						AckRanges:    ackRanges,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(ackRanges[254].First))
					Expect(frame.AckRanges).To(HaveLen(0xFF))
					Expect(frame.validateAckRanges()).To(BeTrue())
				})

				It("skips the lowest ACK ranges, if the gaps are large", func() {
					ackRanges := make([]AckRange, 100)
					// every AckRange will take 4 written ACK ranges
					for i := 1; i <= 100; i++ {
						ackRanges[100-i] = AckRange{First: protocol.PacketNumber(1000 * i), Last: protocol.PacketNumber(1000*i + 1)}
					}
					frameOrig := &AckFrame{
						LargestAcked: ackRanges[0].Last,
						LowestAcked:  ackRanges[len(ackRanges)-1].First,
						AckRanges:    ackRanges,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(ackRanges[255/4].First))
					Expect(frame.validateAckRanges()).To(BeTrue())
				})

				It("works with huge gaps", func() {
					ackRanges := []AckRange{
						{First: 2 * 255 * 200, Last: 2*255*200 + 1},
						{First: 1 * 255 * 200, Last: 1*255*200 + 1},
						{First: 1, Last: 2},
					}
					frameOrig := &AckFrame{
						LargestAcked: ackRanges[0].Last,
						LowestAcked:  ackRanges[len(ackRanges)-1].First,
						AckRanges:    ackRanges,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseAckFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.LowestAcked).To(Equal(ackRanges[1].First))
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
						{First: 1000, Last: 2000},
						{First: 50, Last: 900},
						{First: 10, Last: 23},
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
						{First: 1500, Last: 2000},
						{First: 290, Last: 295},
						{First: 1, Last: 19},
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
						{First: 1500, Last: largestAcked},
						{First: 290, Last: 295},
						{First: 1, Last: 19},
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
				AckRanges:    []AckRange{{First: 1, Last: 10}},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges with Last of the first range unequal to LargestObserved", func() {
			ack := AckFrame{
				LargestAcked: 10,
				AckRanges: []AckRange{
					{First: 8, Last: 9},
					{First: 2, Last: 3},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges with First greater than Last", func() {
			ack := AckFrame{
				LargestAcked: 10,
				AckRanges: []AckRange{
					{First: 8, Last: 10},
					{First: 4, Last: 3},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges with First greater than LargestObserved", func() {
			ack := AckFrame{
				LargestAcked: 5,
				AckRanges: []AckRange{
					{First: 4, Last: 10},
					{First: 1, Last: 2},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges in the wrong order", func() {
			ack := AckFrame{
				LargestAcked: 7,
				AckRanges: []AckRange{
					{First: 2, Last: 2},
					{First: 6, Last: 7},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects with overlapping ACK ranges", func() {
			ack := AckFrame{
				LargestAcked: 7,
				AckRanges: []AckRange{
					{First: 5, Last: 7},
					{First: 2, Last: 5},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges that are part of a larger ACK range", func() {
			ack := AckFrame{
				LargestAcked: 7,
				AckRanges: []AckRange{
					{First: 4, Last: 7},
					{First: 5, Last: 6},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects with directly adjacent ACK ranges", func() {
			ack := AckFrame{
				LargestAcked: 7,
				AckRanges: []AckRange{
					{First: 5, Last: 7},
					{First: 2, Last: 4},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("accepts an ACK with one lost packet", func() {
			ack := AckFrame{
				LargestAcked: 10,
				AckRanges: []AckRange{
					{First: 5, Last: 10},
					{First: 1, Last: 3},
				},
			}
			Expect(ack.validateAckRanges()).To(BeTrue())
		})

		It("accepts an ACK with multiple lost packets", func() {
			ack := AckFrame{
				LargestAcked: 20,
				AckRanges: []AckRange{
					{First: 15, Last: 20},
					{First: 10, Last: 12},
					{First: 1, Last: 3},
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
					{First: 15, Last: 20},
					{First: 5, Last: 8},
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
