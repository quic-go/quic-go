package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet packer", func() {
	var (
		packer          *packetPacker
		publicHeaderLen protocol.ByteCount
		streamFramer    *streamFramer
	)

	BeforeEach(func() {
		fcm := newMockFlowControlHandler()
		fcm.sendWindowSizes[3] = protocol.MaxByteCount
		fcm.sendWindowSizes[5] = protocol.MaxByteCount
		fcm.sendWindowSizes[7] = protocol.MaxByteCount

		cpm := &mockConnectionParametersManager{}
		streamFramer = newStreamFramer(newStreamsMap(nil, cpm), fcm)
		cs, err := handshake.NewCryptoSetup(0, nil, protocol.VersionWhatever, nil, nil, nil, nil)
		Expect(err).ToNot(HaveOccurred())

		packer = &packetPacker{
			cryptoSetup:           cs,
			connectionParameters:  cpm,
			packetNumberGenerator: newPacketNumberGenerator(protocol.SkipPacketAveragePeriodLength),
			streamFramer:          streamFramer,
		}
		publicHeaderLen = 1 + 8 + 2 // 1 flag byte, 8 connection ID, 2 packet number
		packer.version = protocol.Version34
	})

	It("returns nil when no packet is queued", func() {
		p, err := packer.PackPacket(nil, []frames.Frame{}, 0)
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
	})

	It("packs single packets", func() {
		f := &frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}
		streamFramer.AddFrameForRetransmission(f)
		p, err := packer.PackPacket(nil, []frames.Frame{}, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
		b := &bytes.Buffer{}
		f.Write(b, 0)
		Expect(p.frames).To(HaveLen(1))
		Expect(p.raw).To(ContainSubstring(string(b.Bytes())))
	})

	It("packs a ConnectionClose", func() {
		ccf := frames.ConnectionCloseFrame{
			ErrorCode:    0x1337,
			ReasonPhrase: "foobar",
		}
		p, err := packer.PackConnectionClose(&ccf, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(HaveLen(1))
		Expect(p.frames[0]).To(Equal(&ccf))
	})

	It("doesn't send any other frames when sending a ConnectionClose", func() {
		ccf := frames.ConnectionCloseFrame{
			ErrorCode:    0x1337,
			ReasonPhrase: "foobar",
		}
		packer.controlFrames = []frames.Frame{&frames.WindowUpdateFrame{StreamID: 37}}
		streamFramer.AddFrameForRetransmission(&frames.StreamFrame{
			StreamID: 5,
			Data:     []byte("foobar"),
		})
		p, err := packer.PackConnectionClose(&ccf, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(HaveLen(1))
		Expect(p.frames[0]).To(Equal(&ccf))
	})

	It("packs only control frames", func() {
		p, err := packer.PackPacket(nil, []frames.Frame{&frames.RstStreamFrame{}, &frames.WindowUpdateFrame{}}, 0)
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(HaveLen(2))
		Expect(p.raw).NotTo(BeEmpty())
	})

	It("increases the packet number", func() {
		p1, err := packer.PackPacket(nil, []frames.Frame{&frames.RstStreamFrame{}}, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(p1).ToNot(BeNil())
		p2, err := packer.PackPacket(nil, []frames.Frame{&frames.RstStreamFrame{}}, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(p2).ToNot(BeNil())
		Expect(p2.number).To(BeNumerically(">", p1.number))
	})

	It("packs a StopWaitingFrame first", func() {
		packer.packetNumberGenerator.next = 15
		swf := &frames.StopWaitingFrame{LeastUnacked: 10}
		p, err := packer.PackPacket(swf, []frames.Frame{&frames.RstStreamFrame{}}, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
		Expect(p.frames).To(HaveLen(2))
		Expect(p.frames[0]).To(Equal(swf))
	})

	It("sets the LeastUnackedDelta length of a StopWaitingFrame", func() {
		packetNumber := protocol.PacketNumber(0xDECAFB) // will result in a 4 byte packet number
		packer.packetNumberGenerator.next = packetNumber
		swf := &frames.StopWaitingFrame{LeastUnacked: packetNumber - 0x100}
		p, err := packer.PackPacket(swf, []frames.Frame{&frames.RstStreamFrame{}}, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames[0].(*frames.StopWaitingFrame).PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
	})

	It("does not pack a packet containing only a StopWaitingFrame", func() {
		swf := &frames.StopWaitingFrame{LeastUnacked: 10}
		p, err := packer.PackPacket(swf, []frames.Frame{}, 0)
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
	})

	It("packs a packet if it has queued control frames, but no new control frames", func() {
		packer.controlFrames = []frames.Frame{&frames.BlockedFrame{StreamID: 0}}
		p, err := packer.PackPacket(nil, []frames.Frame{}, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
	})

	It("packs many control frames into 1 packets", func() {
		f := &frames.AckFrame{LargestAcked: 1}
		b := &bytes.Buffer{}
		f.Write(b, protocol.VersionWhatever)
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
		minLength, _ := blockedFrame.MinLength(0)
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
		packer.packetNumberGenerator.nextToSkip = 1000
		p, err := packer.PackPacket(nil, []frames.Frame{}, 0)
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(packer.packetNumberGenerator.Peek()).To(Equal(protocol.PacketNumber(1)))
		f := &frames.StreamFrame{
			StreamID: 5,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}
		streamFramer.AddFrameForRetransmission(f)
		p, err = packer.PackPacket(nil, []frames.Frame{}, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
		Expect(p.number).To(Equal(protocol.PacketNumber(1)))
		Expect(packer.packetNumberGenerator.Peek()).To(Equal(protocol.PacketNumber(2)))
	})

	Context("Stream Frame handling", func() {
		It("does not splits a stream frame with maximum size", func() {
			f := &frames.StreamFrame{
				Offset:         1,
				StreamID:       5,
				DataLenPresent: false,
			}
			minLength, _ := f.MinLength(0)
			maxStreamFrameDataLen := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLen - minLength
			f.Data = bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen))
			streamFramer.AddFrameForRetransmission(f)
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
			f1 := &frames.StreamFrame{
				StreamID: 5,
				Offset:   1,
				Data:     bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)),
			}
			f2 := &frames.StreamFrame{
				StreamID: 5,
				Offset:   1,
				Data:     []byte("foobar"),
			}
			streamFramer.AddFrameForRetransmission(f1)
			streamFramer.AddFrameForRetransmission(f2)
			p, err := packer.PackPacket(nil, []frames.Frame{}, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(p.raw).To(HaveLen(int(protocol.MaxPacketSize - 1)))
			Expect(p.frames).To(HaveLen(1))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			p, err = packer.PackPacket(nil, []frames.Frame{}, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(HaveLen(1))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
		})

		It("packs multiple small stream frames into single packet", func() {
			f1 := &frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
			}
			f2 := &frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xBE, 0xEF, 0x13, 0x37},
			}
			f3 := &frames.StreamFrame{
				StreamID: 3,
				Data:     []byte{0xCA, 0xFE},
			}
			streamFramer.AddFrameForRetransmission(f1)
			streamFramer.AddFrameForRetransmission(f2)
			streamFramer.AddFrameForRetransmission(f3)
			p, err := packer.PackPacket(nil, []frames.Frame{}, 0)
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
			f := &frames.StreamFrame{
				StreamID: 7,
				Offset:   1,
			}
			minLength, _ := f.MinLength(0)
			maxStreamFrameDataLen := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLen - minLength
			f.Data = bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)+200)
			streamFramer.AddFrameForRetransmission(f)
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
			f1 := &frames.StreamFrame{
				StreamID: 5,
				Data:     bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)+100),
				Offset:   1,
			}
			f2 := &frames.StreamFrame{
				StreamID: 5,
				Data:     bytes.Repeat([]byte{'f'}, int(maxStreamFrameDataLen)+100),
				Offset:   1,
			}
			streamFramer.AddFrameForRetransmission(f1)
			streamFramer.AddFrameForRetransmission(f2)
			p, err := packer.PackPacket(nil, []frames.Frame{}, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(HaveLen(1))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(p.raw).To(HaveLen(int(protocol.MaxPacketSize)))
			p, err = packer.PackPacket(nil, []frames.Frame{}, 0)
			Expect(p.frames).To(HaveLen(2))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeTrue())
			Expect(p.frames[1].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(err).ToNot(HaveOccurred())
			Expect(p.raw).To(HaveLen(int(protocol.MaxPacketSize)))
			p, err = packer.PackPacket(nil, []frames.Frame{}, 0)
			Expect(p.frames).To(HaveLen(1))
			Expect(p.frames[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			p, err = packer.PackPacket(nil, []frames.Frame{}, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(BeNil())
		})

		It("packs a packet that has the maximum packet size when given a large enough stream frame", func() {
			f := &frames.StreamFrame{
				StreamID: 5,
				Offset:   1,
			}
			minLength, _ := f.MinLength(0)
			f.Data = bytes.Repeat([]byte{'f'}, int(protocol.MaxFrameAndPublicHeaderSize-publicHeaderLen-minLength+1)) // + 1 since MinceLength is 1 bigger than the actual StreamFrame header
			streamFramer.AddFrameForRetransmission(f)
			p, err := packer.PackPacket(nil, []frames.Frame{}, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			Expect(p.raw).To(HaveLen(int(protocol.MaxPacketSize)))
		})

		It("splits a stream frame larger than the maximum size", func() {
			f := &frames.StreamFrame{
				StreamID: 5,
				Offset:   1,
			}
			minLength, _ := f.MinLength(0)
			f.Data = bytes.Repeat([]byte{'f'}, int(protocol.MaxFrameAndPublicHeaderSize-publicHeaderLen-minLength+2)) // + 2 since MinceLength is 1 bigger than the actual StreamFrame header

			streamFramer.AddFrameForRetransmission(f)
			payloadFrames, err := packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
			payloadFrames, err = packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(payloadFrames).To(HaveLen(1))
		})
	})

	Context("Blocked frames", func() {
		It("queues a BLOCKED frame", func() {
			length := 100
			streamFramer.blockedFrameQueue = []*frames.BlockedFrame{{StreamID: 5}}
			f := &frames.StreamFrame{
				StreamID: 5,
				Data:     bytes.Repeat([]byte{'f'}, length),
			}
			streamFramer.AddFrameForRetransmission(f)
			_, err := packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(packer.controlFrames[0]).To(Equal(&frames.BlockedFrame{StreamID: 5}))
		})

		It("removes the dataLen attribute from the last StreamFrame, even if it queued a BLOCKED frame", func() {
			length := 100
			streamFramer.blockedFrameQueue = []*frames.BlockedFrame{{StreamID: 5}}
			f := &frames.StreamFrame{
				StreamID: 5,
				Data:     bytes.Repeat([]byte{'f'}, length),
			}
			streamFramer.AddFrameForRetransmission(f)
			p, err := packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(HaveLen(1))
			Expect(p[0].(*frames.StreamFrame).DataLenPresent).To(BeFalse())
		})

		It("packs a connection-level BlockedFrame", func() {
			streamFramer.blockedFrameQueue = []*frames.BlockedFrame{{StreamID: 0}}
			f := &frames.StreamFrame{
				StreamID: 5,
				Data:     []byte("foobar"),
			}
			streamFramer.AddFrameForRetransmission(f)
			_, err := packer.composeNextPacket(nil, publicHeaderLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(packer.controlFrames[0]).To(Equal(&frames.BlockedFrame{StreamID: 0}))
		})
	})

	It("returns nil if we only have a single STOP_WAITING", func() {
		p, err := packer.PackPacket(&frames.StopWaitingFrame{}, nil, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(p).To(BeNil())
	})

	It("packs a single ACK", func() {
		ack := &frames.AckFrame{LargestAcked: 42}
		p, err := packer.PackPacket(nil, []frames.Frame{ack}, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(p).ToNot(BeNil())
		Expect(p.frames[0]).To(Equal(ack))
	})

	It("does not return nil if we only have a single ACK but request it to be sent", func() {
		p, err := packer.PackPacket(nil, []frames.Frame{&frames.AckFrame{}}, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(p).ToNot(BeNil())
	})

	It("queues a control frame to be sent in the next packet", func() {
		wuf := &frames.WindowUpdateFrame{StreamID: 5}
		packer.QueueControlFrameForNextPacket(wuf)
		p, err := packer.PackPacket(nil, nil, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.frames).To(HaveLen(1))
		Expect(p.frames[0]).To(Equal(wuf))
	})
})
