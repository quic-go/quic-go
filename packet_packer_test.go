package quic

import (
	"bytes"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockSentPacketHandler struct{}

func (h *mockSentPacketHandler) SentPacket(packet *ackhandler.Packet) error         { return nil }
func (h *mockSentPacketHandler) ReceivedAck(ackFrame *frames.AckFrame) error        { return nil }
func (h *mockSentPacketHandler) DequeuePacketForRetransmission() *ackhandler.Packet { return nil }
func (h *mockSentPacketHandler) ProbablyHasPacketForRetransmission() bool           { return false }
func (h *mockSentPacketHandler) BytesInFlight() protocol.ByteCount                  { return 0 }
func (h *mockSentPacketHandler) GetLargestObserved() protocol.PacketNumber          { return 1 }
func (h *mockSentPacketHandler) CongestionAllowsSending() bool                      { panic("not implemented") }
func (h *mockSentPacketHandler) CheckForError() error                               { panic("not implemented") }
func (h *mockSentPacketHandler) TimeOfFirstRTO() time.Time                          { panic("not implemented") }

func newMockSentPacketHandler() ackhandler.SentPacketHandler {
	return &mockSentPacketHandler{}
}

var _ = Describe("Packet packer", func() {
	var (
		packer          *packetPacker
		publicHeaderLen protocol.ByteCount
	)

	BeforeEach(func() {
		packer = &packetPacker{
			cryptoSetup:                 &handshake.CryptoSetup{},
			connectionParametersManager: handshake.NewConnectionParamatersManager(),
			sentPacketHandler:           newMockSentPacketHandler(),
			blockedManager:              newBlockedManager(),
			streamFrameQueue:            newStreamFrameQueue(),
		}
		publicHeaderLen = 1 + 8 + 1 // 1 flag byte, 8 connection ID, 1 packet number
	})

	AfterEach(func() {
		packer.lastPacketNumber = 0
	})

	It("returns nil when no packet is queued", func() {
		p, err := packer.PackPacket(nil, []frames.Frame{})
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
	})

	It("packs single packets", func() {
		f := frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}
		packer.AddStreamFrame(f)
		p, err := packer.PackPacket(nil, []frames.Frame{})
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
		b := &bytes.Buffer{}
		f.Write(b, 0)
		Expect(p.frames).To(HaveLen(1))
		Expect(p.raw).To(ContainSubstring(string(b.Bytes())))
	})

	It("packs a ConnectionCloseFrame", func() {
		ccf := frames.ConnectionCloseFrame{
			ErrorCode:    0x1337,
			ReasonPhrase: "foobar",
		}
		p, err := packer.PackConnectionClose(&ccf)
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(HaveLen(1))
		Expect(p.frames[0]).To(Equal(&ccf))
	})

	It("ignores all other frames when called with onlySendOneControlFrame=true", func() {
		ccf := frames.ConnectionCloseFrame{
			ErrorCode:    0x1337,
			ReasonPhrase: "foobar",
		}
		p, err := packer.packPacket(&frames.StopWaitingFrame{LeastUnacked: 13}, []frames.Frame{&ccf, &frames.WindowUpdateFrame{StreamID: 37}}, true)
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(HaveLen(1))
		Expect(p.frames[0]).To(Equal(&ccf))
	})

	It("packs only control frames", func() {
		p, err := packer.PackPacket(nil, []frames.Frame{&frames.ConnectionCloseFrame{}})
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(HaveLen(1))
		Expect(p.raw).NotTo(BeEmpty())
	})

	It("packs a StopWaitingFrame first", func() {
		swf := &frames.StopWaitingFrame{LeastUnacked: 10}
		p, err := packer.PackPacket(swf, []frames.Frame{&frames.ConnectionCloseFrame{}})
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
		Expect(p.frames).To(HaveLen(2))
		Expect(p.frames[0]).To(Equal(swf))
	})

	It("sets the LeastUnackedDelta length of a StopWaitingFrame", func() {
		packetNumber := protocol.PacketNumber(0xDECAFB) // will result in a 4 byte packet number
		packer.lastPacketNumber = packetNumber - 1
		swf := &frames.StopWaitingFrame{LeastUnacked: packetNumber - 0x100}
		p, err := packer.PackPacket(swf, []frames.Frame{&frames.ConnectionCloseFrame{}})
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames[0].(*frames.StopWaitingFrame).PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
	})

	It("does not pack a packet containing only a StopWaitingFrame", func() {
		swf := &frames.StopWaitingFrame{LeastUnacked: 10}
		p, err := packer.PackPacket(swf, []frames.Frame{})
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
	})

	It("packs a packet if it has queued control frames, but no new control frames", func() {
		packer.controlFrames = []frames.Frame{&frames.BlockedFrame{StreamID: 0}}
		p, err := packer.PackPacket(nil, []frames.Frame{})
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
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
		payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen)
		Expect(err).ToNot(HaveOccurred())
		Expect(payloadFrames).To(HaveLen(maxFramesPerPacket))
		payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen)
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
		payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen)
		Expect(err).ToNot(HaveOccurred())
		Expect(payloadFrames).To(HaveLen(maxFramesPerPacket))
		payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen)
		Expect(err).ToNot(HaveOccurred())
		Expect(payloadFrames).To(HaveLen(10))
	})

	It("only increases the packet number when there is an actual packet to send", func() {
		f := frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}
		packer.AddStreamFrame(f)
		p, err := packer.PackPacket(nil, []frames.Frame{})
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(packer.lastPacketNumber).To(Equal(protocol.PacketNumber(1)))
		p, err = packer.PackPacket(nil, []frames.Frame{})
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(packer.lastPacketNumber).To(Equal(protocol.PacketNumber(1)))
		packer.AddStreamFrame(f)
		p, err = packer.PackPacket(nil, []frames.Frame{})
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(packer.lastPacketNumber).To(Equal(protocol.PacketNumber(2)))
	})

	Context("Stream Frame handling", func() {
		It("does not splits a stream frame with maximum size", func() {
			f := frames.StreamFrame{
				Offset:         1,
				StreamID:       13,
				DataLenPresent: false,
			}
			minLength, _ := f.MinLength()
			maxStreamFrameDataLen := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLen - minLength
			f.Data = bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen))
			packer.AddStreamFrame(f)
			payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
			Expect(payloadFrames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(BeEmpty())
		})

		It("correctly handles a stream frame with one byte less than maximum size", func() {
			maxStreamFrameDataLen := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLen - (1 + 1 + 2) - 1
			f1 := frames.StreamFrame{
				StreamID: 5,
				Offset:   1,
				Data:     bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)),
			}
			f2 := frames.StreamFrame{
				StreamID: 5,
				Offset:   1,
				Data:     []byte("foobar"),
			}
			packer.AddStreamFrame(f1)
			packer.AddStreamFrame(f2)
			p, err := packer.PackPacket(nil, []frames.Frame{})
			Expect(err).ToNot(HaveOccurred())
			Expect(p.raw).To(HaveLen(int(protocol.MaxPacketSize - 1)))
			Expect(p.frames).To(HaveLen(1))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			p, err = packer.PackPacket(nil, []frames.Frame{})
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
			p, err := packer.PackPacket(nil, []frames.Frame{})
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
			payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
			Expect(payloadFrames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(payloadFrames[0].(*frames.StreamFrame).Data).To(HaveLen(int(maxStreamFrameDataLen)))
			payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
			Expect(payloadFrames[0].(*frames.StreamFrame).Data).To(HaveLen(200))
			Expect(payloadFrames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(BeEmpty())
		})

		It("packs 2 stream frames that are too big for one packet correctly", func() {
			maxStreamFrameDataLen := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLen - (1 + 1 + 2)
			f1 := frames.StreamFrame{
				StreamID: 5,
				Data:     bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)+100),
				Offset:   1,
			}
			f2 := frames.StreamFrame{
				StreamID: 5,
				Data:     bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)+100),
				Offset:   1,
			}
			packer.AddStreamFrame(f1)
			packer.AddStreamFrame(f2)
			p, err := packer.PackPacket(nil, []frames.Frame{})
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(HaveLen(1))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(p.raw).To(HaveLen(int(protocol.MaxPacketSize)))
			p, err = packer.PackPacket(nil, []frames.Frame{})
			Expect(p.frames).To(HaveLen(2))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeTrue())
			Expect(p.frames[1].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(err).ToNot(HaveOccurred())
			Expect(p.raw).To(HaveLen(int(protocol.MaxPacketSize)))
			p, err = packer.PackPacket(nil, []frames.Frame{})
			Expect(p.frames).To(HaveLen(1))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			p, err = packer.PackPacket(nil, []frames.Frame{})
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(BeNil())
		})

		It("packs a packet that has the maximum packet size when given a large enough stream frame", func() {
			f := frames.StreamFrame{
				StreamID: 5,
				Offset:   1,
			}
			minLength, _ := f.MinLength()
			f.Data = bytes.Repeat([]byte{'f'}, int(protocol.MaxFrameAndPublicHeaderSize-publicHeaderLen-minLength+1)) // + 1 since MinceLength is 1 bigger than the actual StreamFrame header
			packer.AddStreamFrame(f)
			p, err := packer.PackPacket(nil, []frames.Frame{})
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
			payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
			payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
		})
	})

	Context("Blocked frames", func() {
		It("adds a blocked frame to a packet if there is enough space", func() {
			length := 100
			packer.AddBlocked(5, protocol.ByteCount(length))
			f := frames.StreamFrame{
				StreamID: 5,
				Data:     bytes.Repeat([]byte{'f'}, length),
			}
			packer.AddStreamFrame(f)
			p, err := packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(HaveLen(2))
			Expect(p[0]).To(Equal(&frames.BlockedFrame{StreamID: 5}))
		})

		It("removes the dataLen attribute from the last StreamFrame, even if it inserted a BlockedFrame before", func() {
			length := 100
			packer.AddBlocked(5, protocol.ByteCount(length))
			f := frames.StreamFrame{
				StreamID: 5,
				Data:     bytes.Repeat([]byte{'f'}, length),
			}
			packer.AddStreamFrame(f)
			p, err := packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(HaveLen(2))
			Expect(p[1].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
		})

		It("packs a BlockedFrame in the next packet if the current packet doesn't have enough space", func() {
			dataLen := int(protocol.MaxFrameAndPublicHeaderSize-publicHeaderLen) - (1 + 1 + 2) + 1
			packer.AddBlocked(5, protocol.ByteCount(dataLen))
			f := frames.StreamFrame{
				StreamID: 5,
				Data:     bytes.Repeat([]byte{'f'}, dataLen),
			}
			packer.AddStreamFrame(f)
			p, err := packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(HaveLen(1))
			p, err = packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(HaveLen(1))
			Expect(p[0]).To(Equal(&frames.BlockedFrame{StreamID: 5}))
		})

		It("packs a packet with the maximum size with a BlocedFrame", func() {
			blockedFrame := &frames.BlockedFrame{StreamID: 0x1337}
			blockedFrameLen, _ := blockedFrame.MinLength()
			f1 := frames.StreamFrame{
				StreamID: 5,
				Offset:   1,
			}
			streamFrameHeaderLen, _ := f1.MinLength()
			streamFrameHeaderLen-- // - 1 since MinceLength is 1 bigger than the actual StreamFrame header
			// this is the maximum dataLen of a StreamFrames that fits into one packet
			dataLen := int(protocol.MaxFrameAndPublicHeaderSize - publicHeaderLen - streamFrameHeaderLen - blockedFrameLen)
			packer.AddBlocked(5, protocol.ByteCount(dataLen))
			f1.Data = bytes.Repeat([]byte{'f'}, dataLen)
			packer.AddStreamFrame(f1)
			p, err := packer.PackPacket(nil, []frames.Frame{})
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			Expect(p.raw).To(HaveLen(int(protocol.MaxPacketSize)))
			p, err = packer.PackPacket(nil, []frames.Frame{})
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(BeNil())
		})

		// TODO: fix this once connection-level BlockedFrames are sent out at the right time
		// see https://github.com/lucas-clemente/quic-go/issues/113
		It("packs a connection-level BlockedFrame", func() {
			packer.AddBlocked(0, 0x1337)
			f := frames.StreamFrame{
				StreamID: 5,
				Data:     []byte("foobar"),
			}
			packer.AddStreamFrame(f)
			p, err := packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(HaveLen(2))
			Expect(p[0]).To(Equal(&frames.BlockedFrame{StreamID: 0}))
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
