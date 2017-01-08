package quic

import (
	"github.com/lucas-clemente/quic-go/frames"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Unpacked packet", func() {
	var packet *unpackedPacket
	BeforeEach(func() {
		packet = &unpackedPacket{}
	})

	It("says that an empty packet is not retransmittable", func() {
		Expect(packet.IsRetransmittable()).To(BeFalse())
	})

	It("detects the frame types", func() {
		packet.frames = []frames.Frame{&frames.AckFrame{}}
		Expect(packet.IsRetransmittable()).To(BeFalse())
		packet.frames = []frames.Frame{&frames.BlockedFrame{}}
		Expect(packet.IsRetransmittable()).To(BeTrue())
		packet.frames = []frames.Frame{&frames.GoawayFrame{}}
		Expect(packet.IsRetransmittable()).To(BeTrue())
		packet.frames = []frames.Frame{&frames.PingFrame{}}
		Expect(packet.IsRetransmittable()).To(BeTrue())
		packet.frames = []frames.Frame{&frames.StreamFrame{}}
		Expect(packet.IsRetransmittable()).To(BeTrue())
		packet.frames = []frames.Frame{&frames.RstStreamFrame{}}
		Expect(packet.IsRetransmittable()).To(BeTrue())
		packet.frames = []frames.Frame{&frames.StopWaitingFrame{}}
		Expect(packet.IsRetransmittable()).To(BeFalse())
		packet.frames = []frames.Frame{&frames.WindowUpdateFrame{}}
		Expect(packet.IsRetransmittable()).To(BeTrue())
	})

	It("says that a packet is retransmittable if it contains one retransmittable frame", func() {
		packet.frames = []frames.Frame{
			&frames.AckFrame{},
			&frames.WindowUpdateFrame{},
			&frames.StopWaitingFrame{},
		}
		Expect(packet.IsRetransmittable()).To(BeTrue())
	})
})
