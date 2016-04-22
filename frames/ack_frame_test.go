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
			Expect(frame.HasNACK()).To(Equal(false))
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
			Expect(frame.HasNACK()).To(Equal(true))
			Expect(len(frame.NackRanges)).To(Equal(1))
			Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(3)))
			Expect(frame.NackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(frame.NackRanges[0].LastPacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(b.Len()).To(Equal(0))
		})

		It("parses a frame containing one NACK range with a 48 bit LargestObserved and missingPacketSequenceNumberDelta", func() {
			rangeLength := 3
			b := bytes.NewReader([]byte{(0x4C | 0x20 | 0x03), 0x08, 0x37, 0x13, 0xAD, 0xFB, 0xCA, 0xDE, 0x72, 0x1, 0x1, 0x0, 0xc0, 0x15, 0x0, 0x0, 0x1, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE, byte(rangeLength)})
			frame, err := ParseAckFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(protocol.PacketNumber(0xDECAFBAD1337)))
			Expect(frame.HasNACK()).To(Equal(true))
			Expect(len(frame.NackRanges)).To(Equal(1))
			Expect(frame.NackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(0xDECAFBAD1337 - 0xDEADBEEFCAFE - rangeLength)))
			Expect(frame.NackRanges[0].LastPacketNumber).To(Equal(protocol.PacketNumber(0xDECAFBAD1337 - 0xDEADBEEFCAFE)))
			Expect(b.Len()).To(Equal(0))
		})

		It("parses a frame containing multiple NACK ranges", func() {
			// sent packets 1, 3, 7, 15
			b := bytes.NewReader([]byte{0x60, 0x2, 0xf, 0xb8, 0x1, 0x1, 0x0, 0xe5, 0x58, 0x4, 0x0, 0x3, 0x1, 0x6, 0x1, 0x2, 0x1, 0x0})
			frame, err := ParseAckFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.HasNACK()).To(Equal(true))
			Expect(len(frame.NackRanges)).To(Equal(3))
			Expect(frame.NackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(8)))
			Expect(frame.NackRanges[0].LastPacketNumber).To(Equal(protocol.PacketNumber(14)))
			Expect(frame.NackRanges[1].FirstPacketNumber).To(Equal(protocol.PacketNumber(4)))
			Expect(frame.NackRanges[1].LastPacketNumber).To(Equal(protocol.PacketNumber(6)))
			Expect(frame.NackRanges[2].FirstPacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(frame.NackRanges[2].LastPacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(b.Len()).To(Equal(0))
		})
	})

	Context("GetHighestInOrderPacket", func() {
		It("gets the highest in order packet number for an ACK without NACK ranges", func() {
			frame := AckFrame{LargestObserved: 5}
			Expect(frame.GetHighestInOrderPacketNumber()).To(Equal(protocol.PacketNumber(5)))
		})

		It("gets the highest in order packet number for an ACK with one NACK ranges", func() {
			nackRange := NackRange{FirstPacketNumber: 3, LastPacketNumber: 4}
			frame := AckFrame{
				LargestObserved: 6,
				NackRanges:      []NackRange{nackRange},
			}
			Expect(frame.GetHighestInOrderPacketNumber()).To(Equal(protocol.PacketNumber(2)))
		})

		It("gets the highest in order packet number for an ACK with one NACK ranges", func() {
			nackRanges := []NackRange{
				NackRange{FirstPacketNumber: 9, LastPacketNumber: 11},
				NackRange{FirstPacketNumber: 7, LastPacketNumber: 7},
				NackRange{FirstPacketNumber: 4, LastPacketNumber: 5},
			}
			frame := &AckFrame{
				LargestObserved: 15,
				NackRanges:      nackRanges,
			}
			Expect(frame.GetHighestInOrderPacketNumber()).To(Equal(protocol.PacketNumber(3)))
		})
	})

	Context("when writing", func() {
		It("writes simple frames without NACK ranges", func() {
			b := &bytes.Buffer{}
			frame := AckFrame{
				Entropy:         2,
				LargestObserved: 1,
			}
			err := frame.Write(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()).To(Equal([]byte{0x4c, 0x02, 0x01, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0}))
		})

		It("writes a frame with one NACK range", func() {
			b := &bytes.Buffer{}
			nackRange := NackRange{
				FirstPacketNumber: 2,
				LastPacketNumber:  2,
			}
			frame := AckFrame{
				Entropy:         2,
				LargestObserved: 4,
				NackRanges:      []NackRange{nackRange},
			}
			err := frame.Write(b)
			Expect(err).ToNot(HaveOccurred())
			missingPacketBytes := b.Bytes()[b.Len()-8:]
			Expect(missingPacketBytes[0]).To(Equal(uint8(1))) // numRanges
			Expect(missingPacketBytes[7]).To(Equal(uint8(0))) // rangeLength
			packetNumber := make([]byte, 6)
			copy(packetNumber, missingPacketBytes[1:6])
			Expect(packetNumber).To(BeEquivalentTo([]byte{2, 0, 0, 0, 0, 0}))
		})

		It("writes a frame with multiple NACK ranges", func() {
			b := &bytes.Buffer{}
			nackRange1 := NackRange{
				FirstPacketNumber: 4,
				LastPacketNumber:  6,
			}
			nackRange2 := NackRange{
				FirstPacketNumber: 2,
				LastPacketNumber:  2,
			}
			frame := AckFrame{
				Entropy:         2,
				LargestObserved: 7,
				NackRanges:      []NackRange{nackRange1, nackRange2},
			}
			err := frame.Write(b)
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

		It("has proper max length", func() {
			b := &bytes.Buffer{}
			f := &AckFrame{
				Entropy:         2,
				LargestObserved: 1,
			}
			f.Write(b)
			Expect(f.MaxLength()).To(Equal(b.Len()))
		})

		It("has proper max length with nack ranges", func() {
			b := &bytes.Buffer{}
			f := &AckFrame{
				Entropy:         2,
				LargestObserved: 4,
				NackRanges: []NackRange{
					NackRange{
						FirstPacketNumber: 2,
						LastPacketNumber:  2,
					},
				},
			}
			err := f.Write(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.MaxLength()).To(Equal(b.Len()))
		})
	})

	Context("self-consistency checks", func() {
		It("is self-consistent for ACK frames without NACK ranges", func() {
			b := &bytes.Buffer{}
			frameOrig := &AckFrame{
				Entropy:         0xDE,
				LargestObserved: 6789,
			}
			err := frameOrig.Write(b)
			Expect(err).ToNot(HaveOccurred())
			frame, err := ParseAckFrame(bytes.NewReader(b.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Entropy).To(Equal(frameOrig.Entropy))
			Expect(frame.LargestObserved).To(Equal(frameOrig.LargestObserved))
		})

		It("is self-consistent for ACK frames with NACK ranges", func() {
			b := &bytes.Buffer{}
			nackRanges := []NackRange{
				NackRange{FirstPacketNumber: 9, LastPacketNumber: 11},
				NackRange{FirstPacketNumber: 7, LastPacketNumber: 7},
				NackRange{FirstPacketNumber: 2, LastPacketNumber: 3},
			}
			frameOrig := &AckFrame{
				LargestObserved: 15,
				NackRanges:      nackRanges,
			}
			err := frameOrig.Write(b)
			Expect(err).ToNot(HaveOccurred())
			r := bytes.NewReader(b.Bytes())
			frame, err := ParseAckFrame(r)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(frameOrig.LargestObserved))
			Expect(len(frame.NackRanges)).To(Equal(len(frameOrig.NackRanges)))
			Expect(frame.NackRanges).To(Equal(frameOrig.NackRanges))
		})
	})
})
