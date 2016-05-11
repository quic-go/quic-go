package quic

import (
	"bytes"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockSentPacketHandler struct{}

func (h *mockSentPacketHandler) SentPacket(packet *ackhandler.Packet) error {
	return nil
}

func (h *mockSentPacketHandler) ReceivedAck(ackFrame *frames.AckFrame) (time.Duration, []*ackhandler.Packet, []*ackhandler.Packet, error) {
	return 0, nil, nil, nil
}

func (h *mockSentPacketHandler) DequeuePacketForRetransmission() (packet *ackhandler.Packet) {
	return nil
}

func (h *mockSentPacketHandler) BytesInFlight() protocol.ByteCount {
	return 0
}

func (h *mockSentPacketHandler) GetLargestObserved() protocol.PacketNumber {
	return 1
}

func newMockSentPacketHandler() ackhandler.SentPacketHandler {
	return &mockSentPacketHandler{}
}

var _ = Describe("Packet packer", func() {
	var (
		packer *packetPacker
	)

	BeforeEach(func() {
		aead := &crypto.NullAEAD{}
		packer = &packetPacker{
			aead: aead,
			connectionParametersManager: handshake.NewConnectionParamatersManager(),
			sentPacketHandler:           newMockSentPacketHandler(),
		}
	})

	It("returns nil when no packet is queued", func() {
		p, err := packer.PackPacket(nil, []frames.Frame{}, true)
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
	})

	It("packs single packets", func() {
		f := frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}
		packer.AddStreamFrame(f)
		p, err := packer.PackPacket(nil, []frames.Frame{}, true)
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
		b := &bytes.Buffer{}
		f.Write(b, 1, protocol.PacketNumberLen6, 0)
		Expect(len(p.frames)).To(Equal(1))
		Expect(p.raw).To(ContainSubstring(string(b.Bytes())))
	})

	It("does not pack stream frames if includeStreamFrames=false", func() {
		f := frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}
		packer.AddStreamFrame(f)
		p, err := packer.PackPacket(nil, []frames.Frame{}, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(p).To(BeNil())
	})

	It("packs only control frames", func() {
		p, err := packer.PackPacket(nil, []frames.Frame{&frames.ConnectionCloseFrame{}}, false)
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(len(p.frames)).To(Equal(1))
		Expect(p.raw).NotTo(HaveLen(0))
	})

	It("packs a StopWaitingFrame first", func() {
		swf := &frames.StopWaitingFrame{LeastUnacked: 10}
		p, err := packer.PackPacket(swf, []frames.Frame{&frames.ConnectionCloseFrame{}}, false)
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(len(p.frames)).To(Equal(2))
		Expect(p.frames[0]).To(Equal(swf))
	})

	It("does not pack a packet containing only a StopWaitingFrame", func() {
		swf := &frames.StopWaitingFrame{LeastUnacked: 10}
		p, err := packer.PackPacket(swf, []frames.Frame{}, false)
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
	})

	It("packs many control frames into 1 packets", func() {
		publicHeaderLength := protocol.ByteCount(10)
		f := &frames.AckFrame{LargestObserved: 1}
		b := &bytes.Buffer{}
		f.Write(b, 3, protocol.PacketNumberLen6, 32)
		maxFramesPerPacket := int(protocol.MaxFrameAndPublicHeaderSize-publicHeaderLength) / b.Len()
		var controlFrames []frames.Frame
		for i := 0; i < maxFramesPerPacket; i++ {
			controlFrames = append(controlFrames, f)
		}
		payloadFrames, err := packer.composeNextPacket(nil, controlFrames, publicHeaderLength, true)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(payloadFrames)).To(Equal(maxFramesPerPacket))
		payloadFrames, err = packer.composeNextPacket(nil, []frames.Frame{}, publicHeaderLength, true)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(payloadFrames)).To(BeZero())
	})

	It("only increases the packet number when there is an actual packet to send", func() {
		f := frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}
		packer.AddStreamFrame(f)
		p, err := packer.PackPacket(nil, []frames.Frame{}, true)
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(packer.lastPacketNumber).To(Equal(protocol.PacketNumber(1)))
		p, err = packer.PackPacket(nil, []frames.Frame{}, true)
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(packer.lastPacketNumber).To(Equal(protocol.PacketNumber(1)))
		packer.AddStreamFrame(f)
		p, err = packer.PackPacket(nil, []frames.Frame{}, true)
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(packer.lastPacketNumber).To(Equal(protocol.PacketNumber(2)))
	})

	Context("Stream Frame handling", func() {
		It("does not splits a stream frame with maximum size", func() {
			publicHeaderLength := protocol.ByteCount(12)
			maxStreamFrameDataLen := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLength - (1 + 4 + 8 + 2)
			f := frames.StreamFrame{
				Data:   bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)),
				Offset: 1,
			}
			packer.AddStreamFrame(f)
			payloadFrames, err := packer.composeNextPacket(nil, []frames.Frame{}, publicHeaderLength, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(payloadFrames)).To(Equal(1))
			payloadFrames, err = packer.composeNextPacket(nil, []frames.Frame{}, publicHeaderLength, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(payloadFrames)).To(Equal(0))
		})

		It("packs multiple small stream frames into single packet", func() {
			f1 := frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
			}
			f2 := frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xBE, 0xEF, 0x13, 0x37},
			}
			packer.AddStreamFrame(f1)
			packer.AddStreamFrame(f2)
			p, err := packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(p).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			b := &bytes.Buffer{}
			f1.Write(b, 2, protocol.PacketNumberLen6, 0)
			f2.Write(b, 2, protocol.PacketNumberLen6, 0)
			Expect(len(p.frames)).To(Equal(2))
			Expect(p.raw).To(ContainSubstring(string(b.Bytes())))
		})

		It("splits one stream frame larger than maximum size", func() {
			publicHeaderLength := protocol.ByteCount(5)
			f := frames.StreamFrame{
				StreamID: 7,
				Offset:   1,
			}
			maxStreamFrameDataLen := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLength - f.MinLength() + 1 // + 1 since MinceLength is 1 bigger than the actual StreamFrame header
			f.Data = bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)+200)
			packer.AddStreamFrame(f)
			payloadFrames, err := packer.composeNextPacket(nil, []frames.Frame{}, publicHeaderLength, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(payloadFrames)).To(Equal(1))
			Expect(protocol.ByteCount(len(payloadFrames[0].(*frames.StreamFrame).Data))).To(Equal(maxStreamFrameDataLen))
			payloadFrames, err = packer.composeNextPacket(nil, []frames.Frame{}, publicHeaderLength, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(payloadFrames)).To(Equal(1))
			Expect(len(payloadFrames[0].(*frames.StreamFrame).Data)).To(Equal(200))
			payloadFrames, err = packer.composeNextPacket(nil, []frames.Frame{}, publicHeaderLength, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(payloadFrames)).To(Equal(0))
		})

		It("packs 2 stream frames that are too big for one packet correctly", func() {
			publicHeaderLength := protocol.ByteCount(5)
			maxStreamFrameDataLen := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLength - (1 + 4 + 8 + 2)
			f1 := frames.StreamFrame{
				Data:   bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)+100),
				Offset: 1,
			}
			f2 := frames.StreamFrame{
				Data:   bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)+100),
				Offset: 1,
			}
			packer.AddStreamFrame(f1)
			packer.AddStreamFrame(f2)
			p, err := packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(protocol.ByteCount(len(p.raw))).To(Equal(protocol.MaxPacketSize))
			p, err = packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(protocol.ByteCount(len(p.raw))).To(Equal(protocol.MaxPacketSize))
			p, err = packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			p, err = packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(BeNil())
		})

		It("packs a packet that has the maximum packet size when given a large enough stream frame", func() {
			publicHeaderLength := protocol.ByteCount(3)
			f := frames.StreamFrame{
				Offset: 1,
			}
			f.Data = bytes.Repeat([]byte{'f'}, int(protocol.MaxFrameAndPublicHeaderSize-publicHeaderLength-f.MinLength()+1)) // + 1 since MinceLength is 1 bigger than the actual StreamFrame header
			packer.AddStreamFrame(f)
			p, err := packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			Expect(protocol.ByteCount(len(p.raw))).To(Equal(protocol.MaxPacketSize))
		})

		It("splits a stream frame larger than the maximum size", func() {
			publicHeaderLength := protocol.ByteCount(13)
			f := frames.StreamFrame{
				StreamID: 5,
				Offset:   1,
			}
			f.Data = bytes.Repeat([]byte{'f'}, int(protocol.MaxFrameAndPublicHeaderSize-publicHeaderLength-f.MinLength()+2)) // + 2 since MinceLength is 1 bigger than the actual StreamFrame header

			packer.AddStreamFrame(f)
			payloadFrames, err := packer.composeNextPacket(nil, []frames.Frame{}, publicHeaderLength, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(payloadFrames)).To(Equal(1))
			payloadFrames, err = packer.composeNextPacket(nil, []frames.Frame{}, publicHeaderLength, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(payloadFrames)).To(Equal(1))
		})
	})

	It("says whether it is empty", func() {
		Expect(packer.Empty()).To(BeTrue())
		f := frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}
		packer.AddStreamFrame(f)
		Expect(packer.Empty()).To(BeFalse())
	})
})
