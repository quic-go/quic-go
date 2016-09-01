package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("StopWaitingFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x06, 0x03})
			frame, err := ParseStopWaitingFrame(b, 5, 1, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LeastUnacked).To(Equal(protocol.PacketNumber(2)))
			Expect(b.Len()).To(BeZero())
		})

		It("rejects frames with an invalid LeastUnackedDelta", func() {
			b := bytes.NewReader([]byte{0x06, 0xD})
			_, err := ParseStopWaitingFrame(b, 10, 1, protocol.VersionWhatever)
			Expect(err).To(HaveOccurred())
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x06, 0x03}
			_, err := ParseStopWaitingFrame(bytes.NewReader(data), 5, 1, protocol.VersionWhatever)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseStopWaitingFrame(bytes.NewReader(data[0:i]), 5, 1, protocol.VersionWhatever)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := &StopWaitingFrame{
				LeastUnacked:    10,
				PacketNumber:    13,
				PacketNumberLen: protocol.PacketNumberLen6,
			}
			frame.Write(b, protocol.VersionWhatever)
			Expect(b.Bytes()[0]).To(Equal(uint8(0x06)))
			Expect(b.Bytes()[1:7]).To(Equal([]byte{3, 0, 0, 0, 0, 0}))
		})

		It("errors when PacketNumber was not set", func() {
			b := &bytes.Buffer{}
			frame := &StopWaitingFrame{
				LeastUnacked:    10,
				PacketNumberLen: protocol.PacketNumberLen1,
			}
			err := frame.Write(b, 0)
			Expect(err).To(MatchError(errPacketNumberNotSet))
		})

		It("errors when PacketNumberLen was not set", func() {
			b := &bytes.Buffer{}
			frame := &StopWaitingFrame{
				LeastUnacked: 10,
				PacketNumber: 13,
			}
			err := frame.Write(b, 0)
			Expect(err).To(MatchError(errPacketNumberLenNotSet))
		})

		It("errors when the LeastUnackedDelta would be negative", func() {
			b := &bytes.Buffer{}
			frame := &StopWaitingFrame{
				LeastUnacked:    10,
				PacketNumber:    5,
				PacketNumberLen: protocol.PacketNumberLen1,
			}
			err := frame.Write(b, 0)
			Expect(err).To(MatchError(errLeastUnackedHigherThanPacketNumber))
		})

		Context("LeastUnackedDelta length", func() {
			It("writes a 1-byte LeastUnackedDelta", func() {
				b := &bytes.Buffer{}
				frame := &StopWaitingFrame{
					LeastUnacked:    10,
					PacketNumber:    13,
					PacketNumberLen: protocol.PacketNumberLen1,
				}
				frame.Write(b, 0)
				Expect(b.Len()).To(Equal(2))
				Expect(b.Bytes()[1]).To(Equal(uint8(3)))
			})

			It("writes a 2-byte LeastUnackedDelta", func() {
				b := &bytes.Buffer{}
				frame := &StopWaitingFrame{
					LeastUnacked:    0x10,
					PacketNumber:    0x1300,
					PacketNumberLen: protocol.PacketNumberLen2,
				}
				frame.Write(b, 0)
				Expect(b.Len()).To(Equal(3))
				Expect(b.Bytes()[1:3]).To(Equal([]byte{0xF0, 0x12}))
			})

			It("writes a 4-byte LeastUnackedDelta", func() {
				b := &bytes.Buffer{}
				frame := &StopWaitingFrame{
					LeastUnacked:    0x1000,
					PacketNumber:    0x12345678,
					PacketNumberLen: protocol.PacketNumberLen4,
				}
				frame.Write(b, 0)
				Expect(b.Len()).To(Equal(5))
				Expect(b.Bytes()[1:5]).To(Equal([]byte{0x78, 0x46, 0x34, 0x12}))
			})

			It("writes a 6-byte LeastUnackedDelta", func() {
				b := &bytes.Buffer{}
				frame := &StopWaitingFrame{
					LeastUnacked:    0x10,
					PacketNumber:    0x123456789ABC,
					PacketNumberLen: protocol.PacketNumberLen6,
				}
				frame.Write(b, 0)
				Expect(b.Len()).To(Equal(7))
				Expect(b.Bytes()[1:7]).To(Equal([]byte{0xAC, 0x9A, 0x78, 0x56, 0x34, 0x12}))
			})
		})
	})

	Context("minLength", func() {
		It("calculates the right minLength", func() {
			for _, length := range []protocol.PacketNumberLen{protocol.PacketNumberLen1, protocol.PacketNumberLen2, protocol.PacketNumberLen4, protocol.PacketNumberLen6} {
				frame := &StopWaitingFrame{
					LeastUnacked:    10,
					PacketNumberLen: length,
				}
				Expect(frame.MinLength(protocol.VersionWhatever)).To(Equal(protocol.ByteCount(length + 1)))
			}
		})

		It("errors when packetNumberLen is not set", func() {
			frame := &StopWaitingFrame{
				LeastUnacked: 10,
			}
			_, err := frame.MinLength(0)
			Expect(err).To(MatchError(errPacketNumberLenNotSet))
		})
	})

	Context("self consistency", func() {
		It("reads a stop waiting frame that it wrote", func() {
			packetNumber := protocol.PacketNumber(13)
			frame := &StopWaitingFrame{
				LeastUnacked:    10,
				PacketNumber:    packetNumber,
				PacketNumberLen: protocol.PacketNumberLen4,
			}
			b := &bytes.Buffer{}
			frame.Write(b, 0)
			readframe, err := ParseStopWaitingFrame(bytes.NewReader(b.Bytes()), packetNumber, protocol.PacketNumberLen4, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(readframe.LeastUnacked).To(Equal(frame.LeastUnacked))
		})
	})
})
