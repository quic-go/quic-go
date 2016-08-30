package ackhandler

import (
	"github.com/lucas-clemente/quic-go/frames"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet", func() {
	Context("getFramesForRetransmission", func() {
		var packet Packet
		var streamFrame1, streamFrame2 *frames.StreamFrame
		var ackFrame1, ackFrame2 *frames.AckFrame
		var stopWaitingFrame *frames.StopWaitingFrame
		var rstStreamFrame *frames.RstStreamFrame
		var windowUpdateFrame *frames.WindowUpdateFrame

		BeforeEach(func() {
			streamFrame1 = &frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0x13, 0x37},
			}
			streamFrame2 = &frames.StreamFrame{
				StreamID: 6,
				Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
			}
			ackFrame1 = &frames.AckFrame{
				AckFrameLegacy: &frames.AckFrameLegacy{
					LargestObserved: 13,
					Entropy:         5,
				},
			}
			ackFrame2 = &frames.AckFrame{
				AckFrameLegacy: &frames.AckFrameLegacy{
					LargestObserved: 333,
					Entropy:         17,
				},
			}
			rstStreamFrame = &frames.RstStreamFrame{
				StreamID:  555,
				ErrorCode: 1337,
			}
			stopWaitingFrame = &frames.StopWaitingFrame{
				LeastUnacked: 7331,
				Entropy:      10,
			}
			windowUpdateFrame = &frames.WindowUpdateFrame{
				StreamID: 999,
			}
			packet = Packet{
				PacketNumber: 1337,
				Frames:       []frames.Frame{windowUpdateFrame, streamFrame1, ackFrame1, streamFrame2, rstStreamFrame, ackFrame2, stopWaitingFrame},
			}
		})

		It("gets all StreamFrames", func() {
			streamFrames := packet.GetStreamFramesForRetransmission()
			Expect(streamFrames).To(HaveLen(2))
			Expect(streamFrames).To(ContainElement(streamFrame1))
			Expect(streamFrames).To(ContainElement(streamFrame2))
		})

		It("gets all control frames", func() {
			controlFrames := packet.GetControlFramesForRetransmission()
			Expect(controlFrames).To(HaveLen(2))
			Expect(controlFrames).To(ContainElement(rstStreamFrame))
			Expect(controlFrames).To(ContainElement(windowUpdateFrame))
		})

		It("does not return any ACK frames", func() {
			controlFrames := packet.GetControlFramesForRetransmission()
			Expect(controlFrames).ToNot(ContainElement(ackFrame1))
			Expect(controlFrames).ToNot(ContainElement(ackFrame2))
		})

		It("does not return any ACK frames", func() {
			controlFrames := packet.GetControlFramesForRetransmission()
			Expect(controlFrames).ToNot(ContainElement(stopWaitingFrame))
		})

		It("returns an empty slice of StreamFrames if no StreamFrames are queued", func() {
			// overwrite the globally defined packet here
			packet := Packet{
				PacketNumber: 1337,
				Frames:       []frames.Frame{ackFrame1, rstStreamFrame},
			}
			streamFrames := packet.GetStreamFramesForRetransmission()
			Expect(streamFrames).To(BeEmpty())
		})

		It("returns an empty slice of control frames if no applicable control frames are queued", func() {
			// overwrite the globally defined packet here
			packet := Packet{
				PacketNumber: 1337,
				Frames:       []frames.Frame{streamFrame1, ackFrame1, stopWaitingFrame},
			}
			controlFrames := packet.GetControlFramesForRetransmission()
			Expect(controlFrames).To(BeEmpty())
		})
	})
})
