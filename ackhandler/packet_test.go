package ackhandler

import (
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet", func() {
	Context("getting frames for retransmission", func() {
		ackFrame := &wire.AckFrame{LargestAcked: 13}
		stopWaitingFrame := &wire.StopWaitingFrame{LeastUnacked: 7331}
		windowUpdateFrame := &wire.WindowUpdateFrame{StreamID: 999}

		streamFrame := &wire.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}

		rstStreamFrame := &wire.RstStreamFrame{
			StreamID:  555,
			ErrorCode: 1337,
		}

		It("returns nil if there are no retransmittable frames", func() {
			packet := &Packet{
				Frames: []wire.Frame{ackFrame, stopWaitingFrame},
			}
			Expect(packet.GetFramesForRetransmission()).To(BeNil())
		})

		It("returns all retransmittable frames", func() {
			packet := &Packet{
				Frames: []wire.Frame{
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
