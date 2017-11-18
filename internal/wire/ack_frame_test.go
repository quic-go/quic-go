package wire

import (
	"bytes"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ACK Frame (for IETF QUIC)", func() {
	Context("parsing", func() {
		It("parses an ACK frame without any ranges", func() {
			data := []byte{0xe}
			data = append(data, encodeVarInt(100)...) // largest acked
			data = append(data, encodeVarInt(0)...)   // delay
			data = append(data, encodeVarInt(0)...)   // num blocks
			data = append(data, encodeVarInt(10)...)  // first ack block
			b := bytes.NewReader(data)
			frame, err := ParseAckFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(100)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(90)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses an ACK frame that only acks a single packet", func() {
			data := []byte{0xe}
			data = append(data, encodeVarInt(55)...) // largest acked
			data = append(data, encodeVarInt(0)...)  // delay
			data = append(data, encodeVarInt(0)...)  // num blocks
			data = append(data, encodeVarInt(0)...)  // first ack block
			b := bytes.NewReader(data)
			frame, err := ParseAckFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(55)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(55)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("accepts an ACK frame that acks all packets from 0 to largest", func() {
			data := []byte{0xe}
			data = append(data, encodeVarInt(20)...) // largest acked
			data = append(data, encodeVarInt(0)...)  // delay
			data = append(data, encodeVarInt(0)...)  // num blocks
			data = append(data, encodeVarInt(20)...) // first ack block
			b := bytes.NewReader(data)
			frame, err := ParseAckFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(20)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(0)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("rejects an ACK frame that has a first ACK block which is larger than LargestAcked", func() {
			data := []byte{0xe}
			data = append(data, encodeVarInt(20)...) // largest acked
			data = append(data, encodeVarInt(0)...)  // delay
			data = append(data, encodeVarInt(0)...)  // num blocks
			data = append(data, encodeVarInt(21)...) // first ack block
			b := bytes.NewReader(data)
			_, err := ParseAckFrame(b, versionIETFFrames)
			Expect(err).To(MatchError("invalid first ACK range"))
		})

		It("parses an ACK frame that has a single block", func() {
			data := []byte{0xe}
			data = append(data, encodeVarInt(1000)...) // largest acked
			data = append(data, encodeVarInt(0)...)    // delay
			data = append(data, encodeVarInt(1)...)    // num blocks
			data = append(data, encodeVarInt(100)...)  // first ack block
			data = append(data, encodeVarInt(98)...)   // gap
			data = append(data, encodeVarInt(50)...)   // ack block
			b := bytes.NewReader(data)
			frame, err := ParseAckFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(1000)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(750)))
			Expect(frame.HasMissingRanges()).To(BeTrue())
			Expect(frame.AckRanges).To(Equal([]AckRange{
				AckRange{Last: 1000, First: 900},
				AckRange{Last: 800, First: 750},
			}))
			Expect(b.Len()).To(BeZero())
		})

		It("parses an ACK frame that has a multiple blocks", func() {
			data := []byte{0xe}
			data = append(data, encodeVarInt(100)...) // largest acked
			data = append(data, encodeVarInt(0)...)   // delay
			data = append(data, encodeVarInt(2)...)   // num blocks
			data = append(data, encodeVarInt(0)...)   // first ack block
			data = append(data, encodeVarInt(0)...)   // gap
			data = append(data, encodeVarInt(0)...)   // ack block
			data = append(data, encodeVarInt(1)...)   // gap
			data = append(data, encodeVarInt(1)...)   // ack block
			b := bytes.NewReader(data)
			frame, err := ParseAckFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked).To(Equal(protocol.PacketNumber(100)))
			Expect(frame.LowestAcked).To(Equal(protocol.PacketNumber(94)))
			Expect(frame.HasMissingRanges()).To(BeTrue())
			Expect(frame.AckRanges).To(Equal([]AckRange{
				AckRange{Last: 100, First: 100},
				AckRange{Last: 98, First: 98},
				AckRange{Last: 95, First: 94},
			}))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOF", func() {
			data := []byte{0xe}
			data = append(data, encodeVarInt(1000)...) // largest acked
			data = append(data, encodeVarInt(0)...)    // delay
			data = append(data, encodeVarInt(1)...)    // num blocks
			data = append(data, encodeVarInt(100)...)  // first ack block
			data = append(data, encodeVarInt(98)...)   // gap
			data = append(data, encodeVarInt(50)...)   // ack block
			_, err := ParseAckFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseAckFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("when writing", func() {
		It("writes a frame that acks a single packet", func() {
			buf := &bytes.Buffer{}
			f := &AckFrame{
				LargestAcked: 0xdeadbeef,
				LowestAcked:  0xdeadbeef,
				DelayTime:    18 * time.Second,
			}
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.MinLength(versionIETFFrames)).To(BeEquivalentTo(buf.Len()))
			b := bytes.NewReader(buf.Bytes())
			frame, err := ParseAckFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(f))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("writes a frame that acks many packets", func() {
			buf := &bytes.Buffer{}
			f := &AckFrame{
				LargestAcked: 0xdecafbad,
				LowestAcked:  0x1337,
			}
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.MinLength(versionIETFFrames)).To(BeEquivalentTo(buf.Len()))
			b := bytes.NewReader(buf.Bytes())
			frame, err := ParseAckFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(f))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("writes a frame with a a single gap", func() {
			buf := &bytes.Buffer{}
			f := &AckFrame{
				LargestAcked: 1000,
				LowestAcked:  100,
				AckRanges: []AckRange{
					{First: 400, Last: 1000},
					{First: 100, Last: 200},
				},
			}
			Expect(f.validateAckRanges()).To(BeTrue())
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.MinLength(versionIETFFrames)).To(BeEquivalentTo(buf.Len()))
			b := bytes.NewReader(buf.Bytes())
			frame, err := ParseAckFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(f))
			Expect(frame.HasMissingRanges()).To(BeTrue())
			Expect(b.Len()).To(BeZero())
		})

		It("writes a frame with multiple ranges", func() {
			buf := &bytes.Buffer{}
			f := &AckFrame{
				LargestAcked: 10,
				LowestAcked:  1,
				AckRanges: []AckRange{
					{First: 10, Last: 10},
					{First: 8, Last: 8},
					{First: 5, Last: 6},
					{First: 1, Last: 3},
				},
			}
			Expect(f.validateAckRanges()).To(BeTrue())
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.MinLength(versionIETFFrames)).To(BeEquivalentTo(buf.Len()))
			b := bytes.NewReader(buf.Bytes())
			frame, err := ParseAckFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(f))
			Expect(frame.HasMissingRanges()).To(BeTrue())
			Expect(b.Len()).To(BeZero())
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
