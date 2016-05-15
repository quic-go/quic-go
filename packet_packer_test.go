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

func (h *mockSentPacketHandler) HasPacketForRetransmission() bool {
	return false
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
		packer          *packetPacker
		publicHeaderLen protocol.ByteCount
	)

	BeforeEach(func() {
		aead := &crypto.NullAEAD{}
		packer = &packetPacker{
			aead: aead,
			connectionParametersManager: handshake.NewConnectionParamatersManager(),
			sentPacketHandler:           newMockSentPacketHandler(),
		}
		publicHeaderLen = 1 + 8 + 1 // 1 flag byte, 8 connection ID, 1 packet number
	})

	AfterEach(func() {
		packer.lastPacketNumber = 0
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
		f.Write(b, 0)
		Expect(p.frames).To(HaveLen(1))
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
		Expect(p.frames).To(HaveLen(1))
		Expect(p.raw).NotTo(BeEmpty())
	})

	It("packs a StopWaitingFrame first", func() {
		swf := &frames.StopWaitingFrame{LeastUnacked: 10}
		p, err := packer.PackPacket(swf, []frames.Frame{&frames.ConnectionCloseFrame{}}, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
		Expect(p.frames).To(HaveLen(2))
		Expect(p.frames[0]).To(Equal(swf))
	})

	It("sets the LeastUnackedDelta length of a StopWaitingFrame", func() {
		packetNumber := protocol.PacketNumber(0xDECAFB) // will result in a 4 byte packet number
		packer.lastPacketNumber = packetNumber - 1
		swf := &frames.StopWaitingFrame{LeastUnacked: packetNumber - 0x100}
		p, err := packer.PackPacket(swf, []frames.Frame{&frames.ConnectionCloseFrame{}}, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames[0].(*frames.StopWaitingFrame).PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
	})

	It("does not pack a packet containing only a StopWaitingFrame", func() {
		swf := &frames.StopWaitingFrame{LeastUnacked: 10}
		p, err := packer.PackPacket(swf, []frames.Frame{}, false)
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
	})

	It("packs many control frames into 1 packets", func() {
		f := &frames.AckFrame{LargestObserved: 1}
		b := &bytes.Buffer{}
		f.Write(b, 32)
		maxFramesPerPacket := int(protocol.MaxFrameAndPublicHeaderSize-publicHeaderLen) / b.Len()
		var controlFrames []frames.Frame
		for i := 0; i < maxFramesPerPacket; i++ {
			controlFrames = append(controlFrames, f)
		}
		packer.controlFrames = controlFrames
		payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen, true)
		Expect(err).ToNot(HaveOccurred())
		Expect(payloadFrames).To(HaveLen(maxFramesPerPacket))
		payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen, true)
		Expect(err).ToNot(HaveOccurred())
		Expect(payloadFrames).To(BeEmpty())
	})

	It("packs a lot of control frames into 2 packets if they don't fit into one", func() {
		blockedFrame := &frames.BlockedFrame{
			StreamID: 0x1337,
		}
		minLength, _ := blockedFrame.MinLength()
		maxFramesPerPacket := int(protocol.MaxFrameAndPublicHeaderSize-publicHeaderLen) / int(minLength)
		var controlFrames []frames.Frame
		for i := 0; i < maxFramesPerPacket+10; i++ {
			controlFrames = append(controlFrames, blockedFrame)
		}
		packer.controlFrames = controlFrames
		payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen, true)
		Expect(err).ToNot(HaveOccurred())
		Expect(payloadFrames).To(HaveLen(maxFramesPerPacket))
		payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen, true)
		Expect(err).ToNot(HaveOccurred())
		Expect(payloadFrames).To(HaveLen(10))
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

	Context("WindowUpdate Frame handling", func() {
		It("packs one WindowUpdateFrame", func() {
			f := &frames.WindowUpdateFrame{
				StreamID:   0x1337,
				ByteOffset: 0xDECAFBAD,
			}
			packer.AddWindowUpdateFrame(f)
			payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
			Expect(payloadFrames[0]).To(Equal(f))
		})

		It("packs multiple WindowUpdateFrame", func() {
			f1 := &frames.WindowUpdateFrame{
				StreamID:   0x1337,
				ByteOffset: 0xDECAFBAD,
			}
			f2 := &frames.WindowUpdateFrame{
				StreamID:   0x7331,
				ByteOffset: 0xDABFACED,
			}
			packer.AddWindowUpdateFrame(f1)
			packer.AddWindowUpdateFrame(f2)
			payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(2))
			Expect(payloadFrames).To(ContainElement(f1))
			Expect(payloadFrames).To(ContainElement(f2))
		})

		It("packs a lot of window update frames into 2 packets if they don't fit into one", func() {
			windowUpdateFrame := &frames.WindowUpdateFrame{
				StreamID: 0x1337,
			}
			minLength, _ := windowUpdateFrame.MinLength()
			maxFramesPerPacket := int(protocol.MaxFrameAndPublicHeaderSize-publicHeaderLen) / int(minLength)
			var controlFrames []frames.Frame
			for i := 0; i < maxFramesPerPacket+10; i++ {
				controlFrames = append(controlFrames, windowUpdateFrame)
			}
			packer.controlFrames = controlFrames
			payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(maxFramesPerPacket))
			payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(10))
		})

		It("only packs a WindowUpdateFrame once", func() {
			f := &frames.WindowUpdateFrame{
				StreamID:   0x1337,
				ByteOffset: 0xDECAFBAD,
			}
			packer.AddWindowUpdateFrame(f)
			payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).ToNot(BeNil())
			payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(BeNil())
		})
	})

	Context("Stream Frame handling", func() {
		It("does not splits a stream frame with maximum size", func() {
			f := frames.StreamFrame{
				Offset:         1,
				DataLenPresent: false,
			}
			minLength, _ := f.MinLength()
			maxStreamFrameDataLen := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLen - minLength
			f.Data = bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen))
			packer.AddStreamFrame(f)
			payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
			Expect(payloadFrames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(BeEmpty())
		})

		It("correctly handles a stream frame with one byte less than maximum size", func() {
			maxStreamFrameDataLen := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLen - (1 + 1 + 2) - 1
			f1 := frames.StreamFrame{
				Data:   bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)),
				Offset: 1,
			}
			f2 := frames.StreamFrame{
				Data:   []byte("foobar"),
				Offset: 1,
			}
			packer.AddStreamFrame(f1)
			packer.AddStreamFrame(f2)
			p, err := packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(p.raw).To(HaveLen(int(protocol.MaxPacketSize - 1)))
			Expect(p.frames).To(HaveLen(1))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			p, err = packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
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
			f3 := frames.StreamFrame{
				StreamID: 3,
				Data:     []byte{0xCA, 0xFE},
			}
			packer.AddStreamFrame(f1)
			packer.AddStreamFrame(f2)
			packer.AddStreamFrame(f3)
			p, err := packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(p).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			b := &bytes.Buffer{}
			f1.Write(b, 0)
			f2.Write(b, 0)
			f3.Write(b, 0)
			Expect(p.frames).To(HaveLen(3))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeTrue())
			Expect(p.frames[1].(*frames.StreamFrame).DataLenPresent).To(BeTrue())
			Expect(p.frames[2].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(p.raw).To(ContainSubstring(string(f1.Data)))
			Expect(p.raw).To(ContainSubstring(string(f2.Data)))
			Expect(p.raw).To(ContainSubstring(string(f3.Data)))
		})

		It("splits one stream frame larger than maximum size", func() {
			f := frames.StreamFrame{
				StreamID: 7,
				Offset:   1,
			}
			minLength, _ := f.MinLength()
			maxStreamFrameDataLen := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLen - minLength + 1 // + 1 since MinceLength is 1 bigger than the actual StreamFrame header
			f.Data = bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)+200)
			packer.AddStreamFrame(f)
			payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
			Expect(payloadFrames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(payloadFrames[0].(*frames.StreamFrame).Data).To(HaveLen(int(maxStreamFrameDataLen)))
			payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
			Expect(payloadFrames[0].(*frames.StreamFrame).Data).To(HaveLen(200))
			Expect(payloadFrames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(BeEmpty())
		})

		It("packs 2 stream frames that are too big for one packet correctly", func() {
			maxStreamFrameDataLen := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLen - (1 + 1 + 2)
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
			Expect(p.frames).To(HaveLen(1))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(p.raw).To(HaveLen(int(protocol.MaxPacketSize)))
			p, err = packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(p.frames).To(HaveLen(2))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeTrue())
			Expect(p.frames[1].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(err).ToNot(HaveOccurred())
			Expect(p.raw).To(HaveLen(int(protocol.MaxPacketSize)))
			p, err = packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(p.frames).To(HaveLen(1))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			p, err = packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(BeNil())
		})

		It("packs a packet that has the maximum packet size when given a large enough stream frame", func() {
			f := frames.StreamFrame{
				Offset: 1,
			}
			minLength, _ := f.MinLength()
			f.Data = bytes.Repeat([]byte{'f'}, int(protocol.MaxFrameAndPublicHeaderSize-publicHeaderLen-minLength+1)) // + 1 since MinceLength is 1 bigger than the actual StreamFrame header
			packer.AddStreamFrame(f)
			p, err := packer.PackPacket(nil, []frames.Frame{}, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			Expect(p.raw).To(HaveLen(int(protocol.MaxPacketSize)))
		})

		It("splits a stream frame larger than the maximum size", func() {
			f := frames.StreamFrame{
				StreamID: 5,
				Offset:   1,
			}
			minLength, _ := f.MinLength()
			f.Data = bytes.Repeat([]byte{'f'}, int(protocol.MaxFrameAndPublicHeaderSize-publicHeaderLen-minLength+2)) // + 2 since MinceLength is 1 bigger than the actual StreamFrame header

			packer.AddStreamFrame(f)
			payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
			payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
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
