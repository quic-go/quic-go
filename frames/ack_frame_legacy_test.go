package frames

import (
	"bytes"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AckFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x40, 0xA4, 0x03, 0x23, 0x45, 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC})
			frame, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Entropy).To(Equal(byte(0xA4)))
			Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(0x03)))
			Expect(frame.DelayTime).To(Equal(430464 * time.Microsecond))
			Expect(frame.HasNACK()).To(Equal(false))
			Expect(b.Len()).To(Equal(0))
		})

		It("parses a frame with a 48 bit packet number", func() {
			b := bytes.NewReader([]byte{0x4C, 0xA4, 0x37, 0x13, 0xAD, 0xFB, 0xCA, 0xDE, 0x23, 0x45, 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC})
			frame, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(0xDECAFBAD1337)))
			Expect(b.Len()).To(Equal(0))
		})

		It("completely parses a frame with multiple timestamps", func() {
			b := bytes.NewReader([]byte{0x40, 0xA4, 0x03, 0x23, 0x45, 0x03, 0x02, 0xFF, 0xEE, 0xDD, 0xCC, 0x12, 0x34, 0x56, 0x78, 0x90, 0xA0})
			_, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(0))
		})

		It("parses a frame containing one NACK range", func() {
			b := bytes.NewReader([]byte{0x60, 0x8, 0x3, 0x72, 0x1, 0x1, 0x0, 0xc0, 0x15, 0x0, 0x0, 0x1, 0x1, 0x1})
			frame, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.HasNACK()).To(Equal(true))
			Expect(frame.NackRanges).To(HaveLen(1))
			Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(3)))
			Expect(frame.NackRanges[0]).To(Equal(NackRange{FirstPacketNumber: 1, LastPacketNumber: 2}))
			Expect(b.Len()).To(Equal(0))
		})

		It("parses a frame containing one NACK range with a 48 bit LargestObserved and missingPacketSequenceNumberDelta", func() {
			var rangeLength uint64 = 3
			b := bytes.NewReader([]byte{(0x4C | 0x20 | 0x03), 0x08, 0x37, 0x13, 0xAD, 0xFB, 0xCA, 0xDE, 0x72, 0x1, 0x1, 0x0, 0xc0, 0x15, 0x0, 0x0, 0x1, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE, byte(rangeLength)})
			frame, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(0xDECAFBAD1337)))
			Expect(frame.HasNACK()).To(Equal(true))
			Expect(frame.NackRanges).To(HaveLen(1))
			Expect(frame.NackRanges[0]).To(Equal(NackRange{FirstPacketNumber: protocol.PacketNumber(0xDECAFBAD1337 - 0xDEADBEEFCAFE - rangeLength), LastPacketNumber: 0xDECAFBAD1337 - 0xDEADBEEFCAFE}))
			Expect(b.Len()).To(Equal(0))
		})

		It("parses a frame containing multiple NACK ranges", func() {
			// sent packets 1, 3, 7, 15
			b := bytes.NewReader([]byte{0x60, 0x2, 0xf, 0xb8, 0x1, 0x1, 0x0, 0xe5, 0x58, 0x4, 0x0, 0x3, 0x1, 0x6, 0x1, 0x2, 0x1, 0x0})
			frame, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.HasNACK()).To(Equal(true))
			Expect(frame.NackRanges).To(HaveLen(3))
			Expect(frame.NackRanges[0]).To(Equal(NackRange{FirstPacketNumber: 8, LastPacketNumber: 14}))
			Expect(frame.NackRanges[1]).To(Equal(NackRange{FirstPacketNumber: 4, LastPacketNumber: 6}))
			Expect(frame.NackRanges[2]).To(Equal(NackRange{FirstPacketNumber: 2, LastPacketNumber: 2}))
			Expect(b.Len()).To(Equal(0))
		})

		It("rejects a packet with an invalid NACK range", func() {
			// LargestObserved: 8, NackRange: (8-7-3) to (8-7)
			b := bytes.NewReader([]byte{0x60, 0x8, 0x7, 0x72, 0x1, 0x1, 0x0, 0xc0, 0x15, 0x0, 0x0, 0x1, 0x7, 0x3})
			_, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
			Expect(err).To(MatchError(errInvalidNackRanges))
		})

		It("accepts truncated acks", func() {
			b := bytes.NewReader([]byte{0x50, 0xA4, 0x03, 0x23, 0x45})
			frame, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Truncated).To(BeTrue())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with the largest observed missing", func() {
			b := bytes.NewReader([]byte{0x60, 0x2, 0xf, 0xb8, 0x1, 0x1, 0x0, 0xe5, 0x58, 0x4, 0x0, 0x1, 0x0, 0x0})
			frame, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.HasNACK()).To(Equal(true))
			Expect(frame.NackRanges).To(HaveLen(1))
			Expect(frame.NackRanges[0]).To(Equal(NackRange{FirstPacketNumber: 15, LastPacketNumber: 15}))
			Expect(b.Len()).To(Equal(0))
		})

		Context("contiguous NACK ranges", func() {
			It("parses a frame with a contiguous NACK range spanning two fields", func() {
				b := bytes.NewReader([]byte{0x64, 0x8, 0x2E, 0x01, 0x72, 0x1, 0x1, 0x0, 0xc0, 0x15, 0x0, 0x0, 0x2, 0x1, 0x2b, 0x0, 0xff})
				frame, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(302)))
				Expect(frame.NackRanges).To(HaveLen(1))
				Expect(frame.NackRanges[0]).To(Equal(NackRange{FirstPacketNumber: 2, LastPacketNumber: 301}))
			})

			It("parses a frame with a contiguous NACK range spanning more than two fields", func() {
				b := bytes.NewReader([]byte{0x64, 0x8, 0x16, 0x05, 0x72, 0x1, 0x1, 0x0, 0xc0, 0x15, 0x0, 0x0, 0x6, 0x1, 0x13, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff})
				frame, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(1302)))
				Expect(frame.NackRanges).To(HaveLen(1))
				Expect(frame.NackRanges[0]).To(Equal(NackRange{FirstPacketNumber: 2, LastPacketNumber: 1301}))
			})

			It("parses a frame with two contiguous NACK ranges", func() {
				b := bytes.NewReader([]byte{0x64, 0x8, 0x23, 0x03, 0x72, 0x1, 0x1, 0x0, 0xc0, 0x15, 0x0, 0x0, 0x4, 0x1, 0x8f, 0x0, 0xff, 0x1, 0x8f, 0x0, 0xff})
				frame, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(803)))
				Expect(frame.NackRanges).To(HaveLen(2))
				Expect(frame.NackRanges[0]).To(Equal(NackRange{FirstPacketNumber: 403, LastPacketNumber: 802}))
				Expect(frame.NackRanges[1]).To(Equal(NackRange{FirstPacketNumber: 2, LastPacketNumber: 401}))
			})

			It("rejects a frame with an invalid NACK range", func() {
				// LargestObserved: 280, but NACK range is 301 packets long
				b := bytes.NewReader([]byte{0x64, 0x8, 0x18, 0x01, 0x72, 0x1, 0x1, 0x0, 0xc0, 0x15, 0x0, 0x0, 0x2, 0x1, 0x2b, 0x0, 0xff})
				_, err := ParseAckFrameLegacy(b, protocol.VersionWhatever)
				Expect(err).To(MatchError(errInvalidNackRanges))
			})
		})

		It("errors on EOFs", func() {
			data := []byte{0x64, 0x8, 0x23, 0x03, 0x72, 0x1, 0x1, 0x0, 0xc0, 0x15, 0x0, 0x0, 0x4, 0x1, 0x8f, 0x0, 0xff, 0x1, 0x8f, 0x0, 0xff}
			_, err := ParseAckFrameLegacy(bytes.NewReader(data), 0)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseAckFrameLegacy(bytes.NewReader(data[0:i]), 0)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("GetHighestInOrderPacket", func() {
		It("gets the highest in order packet number for an ACK without NACK ranges", func() {
			frame := AckFrameLegacy{LargestObserved: 5}
			Expect(frame.GetHighestInOrderPacketNumber()).To(Equal(protocol.PacketNumber(5)))
		})

		It("gets the highest in order packet number for an ACK with one NACK ranges", func() {
			nackRange := NackRange{FirstPacketNumber: 3, LastPacketNumber: 4}
			frame := AckFrameLegacy{
				LargestObserved: 6,
				NackRanges:      []NackRange{nackRange},
			}
			Expect(frame.GetHighestInOrderPacketNumber()).To(Equal(protocol.PacketNumber(2)))
		})

		It("gets the highest in order packet number for an ACK with one NACK ranges", func() {
			nackRanges := []NackRange{
				{FirstPacketNumber: 9, LastPacketNumber: 11},
				{FirstPacketNumber: 7, LastPacketNumber: 7},
				{FirstPacketNumber: 4, LastPacketNumber: 5},
			}
			frame := &AckFrameLegacy{
				LargestObserved: 15,
				NackRanges:      nackRanges,
			}
			Expect(frame.GetHighestInOrderPacketNumber()).To(Equal(protocol.PacketNumber(3)))
		})
	})

	Context("NACK range validator", func() {
		It("rejects NACKs with FirstPacketNumber greater than LastPacketNumber", func() {
			nackRange := NackRange{FirstPacketNumber: 7, LastPacketNumber: 6}
			ack := AckFrameLegacy{
				LargestObserved: 10,
				NackRanges:      []NackRange{nackRange},
			}
			Expect(ack.validateNackRanges()).To(BeFalse())
		})

		It("rejects NACKs with FirstPacketNumber greater than LargestObserved", func() {
			nackRange := NackRange{FirstPacketNumber: 6, LastPacketNumber: 6}
			ack := AckFrameLegacy{
				LargestObserved: 5,
				NackRanges:      []NackRange{nackRange},
			}
			Expect(ack.validateNackRanges()).To(BeFalse())
		})

		It("does not reject NACKs with LasterPacketNumber equal to LargestObserved", func() {
			nackRange := NackRange{FirstPacketNumber: 7, LastPacketNumber: 7}
			ack := AckFrameLegacy{
				LargestObserved: 7,
				NackRanges:      []NackRange{nackRange},
			}
			Expect(ack.validateNackRanges()).To(BeTrue())
		})

		It("rejects NACKs with NackRanges in the wrong order", func() {
			nackRanges := []NackRange{
				{FirstPacketNumber: 2, LastPacketNumber: 2},
				{FirstPacketNumber: 6, LastPacketNumber: 6},
			}
			ack := AckFrameLegacy{
				LargestObserved: 7,
				NackRanges:      nackRanges,
			}
			Expect(ack.validateNackRanges()).To(BeFalse())
		})

		It("rejects NACKs with overlapping NackRanges", func() {
			nackRanges := []NackRange{
				{FirstPacketNumber: 5, LastPacketNumber: 6},
				{FirstPacketNumber: 2, LastPacketNumber: 5},
			}
			ack := AckFrameLegacy{
				LargestObserved: 7,
				NackRanges:      nackRanges,
			}
			Expect(ack.validateNackRanges()).To(BeFalse())
		})

		It("accepts an ACK without NACK Ranges", func() {
			ack := AckFrameLegacy{LargestObserved: 7}
			Expect(ack.validateNackRanges()).To(BeTrue())
		})

		It("accepts an ACK with one NACK Ranges", func() {
			nackRange := NackRange{FirstPacketNumber: 6, LastPacketNumber: 8}
			ack := AckFrameLegacy{
				LargestObserved: 10,
				NackRanges:      []NackRange{nackRange},
			}
			Expect(ack.validateNackRanges()).To(BeTrue())
		})

		It("accepts an ACK with multiple NACK Ranges", func() {
			nackRanges := []NackRange{
				{FirstPacketNumber: 6, LastPacketNumber: 7},
				{FirstPacketNumber: 2, LastPacketNumber: 4},
			}
			ack := AckFrameLegacy{
				LargestObserved: 10,
				NackRanges:      nackRanges,
			}
			Expect(ack.validateNackRanges()).To(BeTrue())
		})
	})

	Context("when writing", func() {
		var b *bytes.Buffer
		BeforeEach(func() {
			b = &bytes.Buffer{}
		})

		It("writes simple frames without NACK ranges", func() {
			frame := AckFrameLegacy{
				Entropy:         2,
				LargestObserved: 1,
			}
			err := frame.Write(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			// check all values except the DelayTime
			Expect(b.Bytes()[0:3]).To(Equal([]byte{0x40, 0x02, 0x01}))
			Expect(b.Bytes()[5:]).To(Equal([]byte{1, 0, 0, 0, 0, 0}))
		})

		It("calculates the DelayTime", func() {
			frame := AckFrameLegacy{
				LargestObserved:    5,
				PacketReceivedTime: time.Now().Add(-750 * time.Millisecond),
			}
			frame.Write(b, protocol.VersionWhatever)
			Expect(frame.DelayTime).To(BeNumerically("~", 750*time.Millisecond, 10*time.Millisecond))
			delayTime := frame.DelayTime
			var b2 bytes.Buffer
			utils.WriteUfloat16(&b2, uint64(delayTime/time.Microsecond))
			Expect(b.Bytes()[3:5]).To(Equal(b2.Bytes()))
		})

		It("writes a frame with one NACK range", func() {
			frame := AckFrameLegacy{
				Entropy:         2,
				LargestObserved: 4,
				NackRanges:      []NackRange{{FirstPacketNumber: 2, LastPacketNumber: 2}},
			}
			err := frame.Write(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			missingPacketBytes := b.Bytes()[b.Len()-8:]
			Expect(missingPacketBytes[0]).To(Equal(uint8(1))) // numRanges
			Expect(missingPacketBytes[7]).To(Equal(uint8(0))) // rangeLength
			packetNumber := make([]byte, 6)
			copy(packetNumber, missingPacketBytes[1:6])
			Expect(packetNumber).To(BeEquivalentTo([]byte{2, 0, 0, 0, 0, 0}))
		})

		It("writes a frame with multiple NACK ranges", func() {
			nackRange1 := NackRange{FirstPacketNumber: 4, LastPacketNumber: 6}
			nackRange2 := NackRange{FirstPacketNumber: 2, LastPacketNumber: 2}
			frame := AckFrameLegacy{
				Entropy:         2,
				LargestObserved: 7,
				NackRanges:      []NackRange{nackRange1, nackRange2},
			}
			err := frame.Write(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			missingPacketBytes := b.Bytes()[b.Len()-(1+2*7):]
			Expect(missingPacketBytes[0]).To(Equal(uint8(2)))      // numRanges
			Expect(missingPacketBytes[7]).To(Equal(uint8(3 - 1)))  // rangeLength #1
			Expect(missingPacketBytes[14]).To(Equal(uint8(1 - 1))) // rangeLength #2
			packetNumber1 := make([]byte, 6)
			packetNumber2 := make([]byte, 6)
			copy(packetNumber1, missingPacketBytes[1:6])
			copy(packetNumber2, missingPacketBytes[8:13])
			Expect(packetNumber1).To(BeEquivalentTo([]byte{1, 0, 0, 0, 0, 0}))
			Expect(packetNumber2).To(BeEquivalentTo([]byte{1, 0, 0, 0, 0, 0}))
		})

		Context("contiguous NACK ranges", func() {
			It("writes the largest possible NACK range that does not require to be written in contiguous form", func() {
				frame := AckFrameLegacy{
					Entropy:         2,
					LargestObserved: 258,
					NackRanges:      []NackRange{{FirstPacketNumber: 2, LastPacketNumber: 257}},
				}
				err := frame.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				missingPacketBytes := b.Bytes()[b.Len()-(1+7):]
				Expect(missingPacketBytes[0]).To(Equal(uint8(1)))                   // numRanges
				Expect(missingPacketBytes[1:7]).To(Equal([]byte{1, 0, 0, 0, 0, 0})) // missingPacketSequenceNumberDelta
				Expect(missingPacketBytes[7]).To(Equal(uint8(0xFF)))                // rangeLength
			})

			It("writes a frame with a contiguous NACK range", func() {
				frame := AckFrameLegacy{
					Entropy:         2,
					LargestObserved: 302,
					NackRanges:      []NackRange{{FirstPacketNumber: 2, LastPacketNumber: 301}},
				}
				err := frame.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				missingPacketBytes := b.Bytes()[b.Len()-(1+2*7):]
				Expect(missingPacketBytes[0]).To(Equal(uint8(2)))                    // numRanges
				Expect(missingPacketBytes[1:7]).To(Equal([]byte{1, 0, 0, 0, 0, 0}))  // missingPacketSequenceNumberDelta #1
				Expect(missingPacketBytes[7]).To(Equal(uint8(43)))                   // rangeLength #1
				Expect(missingPacketBytes[8:14]).To(Equal([]byte{0, 0, 0, 0, 0, 0})) // missingPacketSequenceNumberDelta #2
				Expect(missingPacketBytes[14]).To(Equal(uint8(0xFF)))                // rangeLength #2
			})

			It("writes a frame with the smallest NACK ranges that requires a contiguous NACK range", func() {
				frame := AckFrameLegacy{
					Entropy:         2,
					LargestObserved: 259,
					NackRanges:      []NackRange{{FirstPacketNumber: 2, LastPacketNumber: 258}},
				}
				err := frame.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				missingPacketBytes := b.Bytes()[b.Len()-(1+2*7):]
				Expect(missingPacketBytes[0]).To(Equal(uint8(2)))                    // numRanges
				Expect(missingPacketBytes[1:7]).To(Equal([]byte{1, 0, 0, 0, 0, 0}))  // missingPacketSequenceNumberDelta #1
				Expect(missingPacketBytes[7]).To(Equal(uint8(0)))                    // rangeLength #1
				Expect(missingPacketBytes[8:14]).To(Equal([]byte{0, 0, 0, 0, 0, 0})) // missingPacketSequenceNumberDelta #2
				Expect(missingPacketBytes[14]).To(Equal(uint8(0xFF)))                // rangeLength #2
			})

			It("writes a frame with a long contiguous NACK range", func() {
				frame := AckFrameLegacy{
					Entropy:         2,
					LargestObserved: 603,
					NackRanges:      []NackRange{{FirstPacketNumber: 2, LastPacketNumber: 601}},
				}
				err := frame.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				missingPacketBytes := b.Bytes()[b.Len()-(1+3*7):]
				Expect(missingPacketBytes[0]).To(Equal(uint8(3)))                     // numRanges
				Expect(missingPacketBytes[1:7]).To(Equal([]byte{2, 0, 0, 0, 0, 0}))   // missingPacketSequenceNumberDelta #1
				Expect(missingPacketBytes[7]).To(Equal(uint8(87)))                    // rangeLength #1
				Expect(missingPacketBytes[8:14]).To(Equal([]byte{0, 0, 0, 0, 0, 0}))  // missingPacketSequenceNumberDelta #2
				Expect(missingPacketBytes[14]).To(Equal(uint8(0xFF)))                 // rangeLength #2
				Expect(missingPacketBytes[15:21]).To(Equal([]byte{0, 0, 0, 0, 0, 0})) // missingPacketSequenceNumberDelta #3
				Expect(missingPacketBytes[21]).To(Equal(uint8(0xFF)))                 // rangeLength #3
			})

			It("writes a frame with two contiguous NACK range", func() {
				nackRange1 := NackRange{FirstPacketNumber: 2, LastPacketNumber: 351}
				nackRange2 := NackRange{FirstPacketNumber: 355, LastPacketNumber: 654}
				frame := AckFrameLegacy{
					Entropy:         2,
					LargestObserved: 655,
					NackRanges:      []NackRange{nackRange2, nackRange1},
				}
				err := frame.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				missingPacketBytes := b.Bytes()[b.Len()-(1+4*7):]
				Expect(missingPacketBytes[0]).To(Equal(uint8(4)))                     // numRanges
				Expect(missingPacketBytes[1:7]).To(Equal([]byte{1, 0, 0, 0, 0, 0}))   // missingPacketSequenceNumberDelta #1
				Expect(missingPacketBytes[7]).To(Equal(uint8(43)))                    // rangeLength #1
				Expect(missingPacketBytes[8:14]).To(Equal([]byte{0, 0, 0, 0, 0, 0}))  // missingPacketSequenceNumberDelta #2
				Expect(missingPacketBytes[14]).To(Equal(uint8(0xFF)))                 // rangeLength #2
				Expect(missingPacketBytes[15:21]).To(Equal([]byte{3, 0, 0, 0, 0, 0})) // missingPacketSequenceNumberDelta #3
				Expect(missingPacketBytes[21]).To(Equal(uint8(93)))                   // rangeLength #3
				Expect(missingPacketBytes[22:28]).To(Equal([]byte{0, 0, 0, 0, 0, 0})) // missingPacketSequenceNumberDelta #4
				Expect(missingPacketBytes[28]).To(Equal(uint8(0xFF)))                 // rangeLength #4
			})

			Context("LargestObserved length", func() {
				It("writes a 1 byte LargestObserved value", func() {
					frame := AckFrameLegacy{
						LargestObserved: 7,
					}
					err := frame.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x4C).To(Equal(uint8(0x40)))
					Expect(b.Bytes()[2]).To(Equal(uint8(7)))
				})

				It("writes a 2 byte LargestObserved value", func() {
					frame := AckFrameLegacy{
						LargestObserved: 0x1337,
					}
					err := frame.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x4C).To(Equal(uint8(0x44)))
					Expect(b.Bytes()[2:4]).To(Equal([]byte{0x37, 0x13}))
				})

				It("writes a 4 byte LargestObserved value", func() {
					frame := AckFrameLegacy{
						LargestObserved: 0xDECAFBAD,
					}
					err := frame.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x4C).To(Equal(uint8(0x48)))
					Expect(b.Bytes()[2:6]).To(Equal([]byte{0xAD, 0xFB, 0xCA, 0xDE}))
				})

				It("writes a 6 byte LargestObserved value", func() {
					frame := AckFrameLegacy{
						LargestObserved: 0xDEADBEEFCAFE,
					}
					err := frame.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x4C).To(Equal(uint8(0x4C)))
					Expect(b.Bytes()[2:8]).To(Equal([]byte{0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE}))
				})
			})
		})

		Context("min length", func() {
			It("has proper min length", func() {
				f := &AckFrameLegacy{
					Entropy:         2,
					LargestObserved: 1,
				}
				f.Write(b, 2)
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has proper min length with a large LargestObserved", func() {
				f := &AckFrameLegacy{
					Entropy:         2,
					LargestObserved: 0xDEADBEEFCAFE,
				}
				f.Write(b, 2)
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has proper min length with NACK ranges", func() {
				f := &AckFrameLegacy{
					Entropy:         2,
					LargestObserved: 4,
					NackRanges:      []NackRange{{FirstPacketNumber: 2, LastPacketNumber: 2}},
				}
				err := f.Write(b, protocol.Version33)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has proper min length with a continuous NACK ranges", func() {
				f := &AckFrameLegacy{
					Entropy:         2,
					LargestObserved: 3000,
					NackRanges:      []NackRange{{FirstPacketNumber: 2, LastPacketNumber: 2000}},
				}
				err := f.Write(b, protocol.Version33)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})
		})
	})

	Context("self-consistency checks", func() {
		var b *bytes.Buffer
		BeforeEach(func() {
			b = &bytes.Buffer{}
		})

		It("is self-consistent for ACK frames without NACK ranges", func() {
			frameOrig := &AckFrameLegacy{
				Entropy:         0xDE,
				LargestObserved: 6789,
			}
			err := frameOrig.Write(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			frame, err := ParseAckFrameLegacy(bytes.NewReader(b.Bytes()), protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Entropy).To(Equal(frameOrig.Entropy))
			Expect(frame.LargestObserved).To(Equal(frameOrig.LargestObserved))
		})

		It("is self-consistent for ACK frames with NACK ranges", func() {
			nackRanges := []NackRange{
				{FirstPacketNumber: 9, LastPacketNumber: 11},
				{FirstPacketNumber: 7, LastPacketNumber: 7},
				{FirstPacketNumber: 2, LastPacketNumber: 3},
			}
			frameOrig := &AckFrameLegacy{
				LargestObserved: 15,
				NackRanges:      nackRanges,
			}
			err := frameOrig.Write(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			r := bytes.NewReader(b.Bytes())
			frame, err := ParseAckFrameLegacy(r, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(frameOrig.LargestObserved))
			Expect(frame.NackRanges).To(HaveLen(len(frameOrig.NackRanges)))
			Expect(frame.NackRanges).To(Equal(frameOrig.NackRanges))
		})

		It("is self-consistent for ACK frames with contiguous NACK ranges", func() {
			nackRanges := []NackRange{
				{FirstPacketNumber: 500, LastPacketNumber: 1500},
				{FirstPacketNumber: 350, LastPacketNumber: 351},
				{FirstPacketNumber: 2, LastPacketNumber: 306},
			}
			frameOrig := &AckFrameLegacy{
				LargestObserved: 1600,
				NackRanges:      nackRanges,
			}
			err := frameOrig.Write(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			r := bytes.NewReader(b.Bytes())
			frame, err := ParseAckFrameLegacy(r, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(frameOrig.LargestObserved))
			Expect(frame.NackRanges).To(HaveLen(len(frameOrig.NackRanges)))
			Expect(frame.NackRanges).To(Equal(frameOrig.NackRanges))
		})
	})
})
