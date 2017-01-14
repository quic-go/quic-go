package ackhandler

import (
	"github.com/lucas-clemente/quic-go/frames"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet", func() {
	Context("getting frames for retransmission", func() {
		ackFrame := &frames.AckFrame{LargestAcked: 13}
		stopWaitingFrame := &frames.StopWaitingFrame{LeastUnacked: 7331}
		windowUpdateFrame := &frames.WindowUpdateFrame{StreamID: 999}

		streamFrame := &frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}

		rstStreamFrame := &frames.RstStreamFrame{
			StreamID:  555,
			ErrorCode: 1337,
		}

		It("returns nil if there are no retransmittable frames", func() {
			packet := &Packet{
				Frames: []frames.Frame{ackFrame, stopWaitingFrame},
			}
			Expect(packet.GetFramesForRetransmission()).To(BeNil())
		})

		It("returns all retransmittable frames", func() {
			packet := &Packet{
				Frames: []frames.Frame{
					windowUpdateFrame,
					ackFrame,
					stopWaitingFrame,
					streamFrame,
					rstStreamFrame,
				},
			}
			fs := packet.GetFramesForRetransmission()
			Expect(fs).To(ContainElement(streamFrame))
			Expect(fs).To(ContainElement(rstStreamFrame))
			Expect(fs).To(ContainElement(windowUpdateFrame))
			Expect(fs).ToNot(ContainElement(stopWaitingFrame))
			Expect(fs).ToNot(ContainElement(ackFrame))
		})

	})
})
