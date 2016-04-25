package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("StopWaitingFrame", func() {
	Context("stop waiting frames", func() {
		Context("when parsing", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x06, 0xA4, 0x03})
				frame, err := ParseStopWaitingFrame(b, 5, 1)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.Entropy).To(Equal(byte(0xA4)))
				Expect(frame.LeastUnacked).To(Equal(protocol.PacketNumber(2)))
			})

			It("rejects frames with an invalid LeastUnackedDelta", func() {
				b := bytes.NewReader([]byte{0x06, 0xA4, 0xD})
				_, err := ParseStopWaitingFrame(b, 10, 1)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("when writing", func() {
			It("writes a sample frame", func() {
				b := &bytes.Buffer{}
				packetNumber := protocol.PacketNumber(13)
				frame := &StopWaitingFrame{
					LeastUnacked: 10,
					Entropy:      0xE,
				}
				frame.Write(b, packetNumber, 6)
				Expect(b.Bytes()[0]).To(Equal(uint8(0x06)))
				// todo: check more
			})
		})

		Context("self consistency", func() {
			It("reads a stop waiting frame that it wrote", func() {
				packetNumber := protocol.PacketNumber(13)
				frame := &StopWaitingFrame{
					LeastUnacked: 10,
					Entropy:      0xE,
				}
				b := &bytes.Buffer{}
				frame.Write(b, packetNumber, 6)
				readframe, err := ParseStopWaitingFrame(bytes.NewReader(b.Bytes()), packetNumber, 6)
				Expect(err).ToNot(HaveOccurred())
				Expect(readframe.Entropy).To(Equal(frame.Entropy))
				Expect(readframe.LeastUnacked).To(Equal(frame.LeastUnacked))
			})
		})
	})
})
