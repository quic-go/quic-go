package quic

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet packer (legacy)", func() {
	const maxPacketSize protocol.ByteCount = 1357
	var (
		packer         *packetPackerLegacy
		framer         *MockFrameSource
		ackFramer      *MockAckFrameSource
		cryptoStream   *MockCryptoStream
		sealingManager *MockSealingManager
		sealer         *mocks.MockSealer
		divNonce       []byte
	)

	expectAppendStreamFrames := func(frames ...wire.Frame) {
		framer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(fs []wire.Frame, _ protocol.ByteCount) []wire.Frame {
			return append(fs, frames...)
		})
	}

	expectAppendControlFrames := func(frames ...wire.Frame) {
		framer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(fs []wire.Frame, _ protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
			var length protocol.ByteCount
			for _, f := range frames {
				length += f.Length(packer.version)
			}
			return append(fs, frames...), length
		})
	}

	BeforeEach(func() {
		rand.Seed(GinkgoRandomSeed())
		version := versionGQUICFrames
		mockSender := NewMockStreamSender(mockCtrl)
		mockSender.EXPECT().onHasStreamData(gomock.Any()).AnyTimes()
		cryptoStream = NewMockCryptoStream(mockCtrl)
		framer = NewMockFrameSource(mockCtrl)
		ackFramer = NewMockAckFrameSource(mockCtrl)
		sealingManager = NewMockSealingManager(mockCtrl)
		sealer = mocks.NewMockSealer(mockCtrl)
		sealer.EXPECT().Overhead().Return(9).AnyTimes()
		sealer.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(dst, src []byte, pn protocol.PacketNumber, associatedData []byte) []byte {
			return append(src, bytes.Repeat([]byte{0}, 9)...)
		}).AnyTimes()

		divNonce = bytes.Repeat([]byte{'e'}, 32)

		packer = newPacketPackerLegacy(
			protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			func(protocol.PacketNumber) protocol.PacketNumberLen { return protocol.PacketNumberLen2 },
			&net.TCPAddr{},
			divNonce,
			cryptoStream,
			sealingManager,
			framer,
			ackFramer,
			protocol.PerspectiveServer,
			version,
		)
		packer.hasSentPacket = true
		packer.version = version
		packer.maxPacketSize = maxPacketSize
	})

	It("returns nil when no packet is queued", func() {
		sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
		ackFramer.EXPECT().GetAckFrame()
		cryptoStream.EXPECT().hasData()
		framer.EXPECT().AppendControlFrames(nil, gomock.Any())
		framer.EXPECT().AppendStreamFrames(nil, gomock.Any())
		p, err := packer.PackPacket()
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
	})

	It("packs single packets", func() {
		sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
		cryptoStream.EXPECT().hasData()
		ackFramer.EXPECT().GetAckFrame()
		expectAppendControlFrames()
		f := &wire.StreamFrame{
			StreamID: 5,
			Data:     []byte{0xDE, 0xCA, 0xFB, 0xAD},
		}
		expectAppendStreamFrames(f)
		p, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
		b := &bytes.Buffer{}
		f.Write(b, packer.version)
		Expect(p.frames).To(Equal([]wire.Frame{f}))
		Expect(p.raw).To(ContainSubstring(b.String()))
	})

	It("stores the encryption level a packet was sealed with", func() {
		sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
		cryptoStream.EXPECT().hasData()
		ackFramer.EXPECT().GetAckFrame()
		expectAppendControlFrames()
		expectAppendStreamFrames(&wire.StreamFrame{
			StreamID: 5,
			Data:     []byte("foobar"),
		})
		p, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p.encryptionLevel).To(Equal(protocol.EncryptionForwardSecure))
	})

	Context("generating a packet header", func() {
		Context("Public Header", func() {
			It("doesn't set the source connection ID", func() {
				ph := packer.getHeader(protocol.EncryptionForwardSecure)
				Expect(ph.SrcConnectionID).To(BeEmpty())
			})

			It("it omits the connection ID for forward-secure packets", func() {
				packer.version = protocol.Version43
				ph := packer.getHeader(protocol.EncryptionForwardSecure)
				Expect(ph.DestConnectionID.Len()).ToNot(BeZero())
				packer.HandleTransportParameters(&handshake.TransportParameters{
					OmitConnectionID: true,
				})
				ph = packer.getHeader(protocol.EncryptionForwardSecure)
				Expect(ph.DestConnectionID.Len()).To(BeZero())
			})

			It("doesn't omit the connection ID for non-forward-secure packets", func() {
				packer.HandleTransportParameters(&handshake.TransportParameters{
					OmitConnectionID: true,
				})
				ph := packer.getHeader(protocol.EncryptionSecure)
				Expect(ph.DestConnectionID.Len()).ToNot(BeZero())
			})

			It("adds the Version Flag to the Public Header before the crypto handshake is finished", func() {
				packer.perspective = protocol.PerspectiveClient
				ph := packer.getHeader(protocol.EncryptionSecure)
				Expect(ph.VersionFlag).To(BeTrue())
			})

			It("doesn't add the Version Flag to the Public Header for forward-secure packets", func() {
				packer.perspective = protocol.PerspectiveClient
				ph := packer.getHeader(protocol.EncryptionForwardSecure)
				Expect(ph.VersionFlag).To(BeFalse())
			})

			Context("diversificaton nonces", func() {
				It("doesn't include a div nonce, when sending a packet with initial encryption", func() {
					ph := packer.getHeader(protocol.EncryptionUnencrypted)
					Expect(ph.DiversificationNonce).To(BeEmpty())
				})

				It("includes a div nonce, when sending a packet with secure encryption", func() {
					ph := packer.getHeader(protocol.EncryptionSecure)
					Expect(ph.DiversificationNonce).To(Equal(divNonce))
				})

				It("doesn't include a div nonce, when sending a packet with forward-secure encryption", func() {
					ph := packer.getHeader(protocol.EncryptionForwardSecure)
					Expect(ph.DiversificationNonce).To(BeEmpty())
				})

				It("doesn't send a div nonce as a client", func() {
					packer.perspective = protocol.PerspectiveClient
					ph := packer.getHeader(protocol.EncryptionSecure)
					Expect(ph.DiversificationNonce).To(BeEmpty())
				})
			})
		})

		Context("Header (for gQUIC 44)", func() {
			BeforeEach(func() {
				packer.version = protocol.Version44
			})

			It("sends an Initial packet as the first packets, for the client", func() {
				packer.perspective = protocol.PerspectiveClient
				packer.hasSentPacket = false
				h := packer.getHeader(protocol.EncryptionUnencrypted)
				Expect(h.IsLongHeader).To(BeTrue())
				Expect(h.Type).To(Equal(protocol.PacketTypeInitial))
				Expect(h.Version).To(Equal(protocol.Version44))
				Expect(h.DestConnectionID).To(Equal(packer.destConnID))
				Expect(h.SrcConnectionID).To(Equal(packer.srcConnID))
				Expect(h.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
			})

			It("sends a Handshake for non-forward-secure packets, for the server", func() {
				packer.perspective = protocol.PerspectiveServer
				h := packer.getHeader(protocol.EncryptionUnencrypted)
				Expect(h.IsLongHeader).To(BeTrue())
				Expect(h.Type).To(Equal(protocol.PacketTypeHandshake))
				Expect(h.Version).To(Equal(protocol.Version44))
				Expect(h.DestConnectionID).To(Equal(packer.destConnID))
				Expect(h.SrcConnectionID).To(Equal(packer.srcConnID))
				Expect(h.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
			})

			It("sets the Diversification Nonce for secure packets", func() {
				packer.perspective = protocol.PerspectiveServer
				Expect(divNonce).ToNot(BeEmpty())
				h := packer.getHeader(protocol.EncryptionSecure)
				Expect(h.IsLongHeader).To(BeTrue())
				Expect(h.Version).To(Equal(protocol.Version44))
				Expect(h.Type).To(Equal(protocol.PacketType0RTT))
				Expect(h.DiversificationNonce).To(Equal(divNonce))
			})

			It("uses the Short Header for forward-secure packets", func() {
				h := packer.getHeader(protocol.EncryptionForwardSecure)
				Expect(h.IsLongHeader).To(BeFalse())
				Expect(h.IsPublicHeader).To(BeFalse())
				Expect(h.DestConnectionID).To(Equal(packer.destConnID))
			})
		})
	})

	It("packs a CONNECTION_CLOSE", func() {
		ccf := wire.ConnectionCloseFrame{
			ErrorCode:    0x1337,
			ReasonPhrase: "foobar",
		}
		sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
		p, err := packer.PackConnectionClose(&ccf)
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(HaveLen(1))
		Expect(p.frames[0]).To(Equal(&ccf))
	})

	It("doesn't send any other frames when sending a CONNECTION_CLOSE", func() {
		// expect no framer.PopStreamFrames
		ccf := &wire.ConnectionCloseFrame{
			ErrorCode:    0x1337,
			ReasonPhrase: "foobar",
		}
		sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
		p, err := packer.PackConnectionClose(ccf)
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(Equal([]wire.Frame{ccf}))
	})

	It("packs control frames", func() {
		sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
		cryptoStream.EXPECT().hasData()
		ackFramer.EXPECT().GetAckFrame()
		frames := []wire.Frame{&wire.RstStreamFrame{}, &wire.MaxDataFrame{}}
		expectAppendControlFrames(frames...)
		expectAppendStreamFrames()
		p, err := packer.PackPacket()
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(Equal(frames))
		Expect(p.raw).NotTo(BeEmpty())
	})

	It("increases the packet number", func() {
		sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer).Times(2)
		cryptoStream.EXPECT().hasData().Times(2)
		ackFramer.EXPECT().GetAckFrame().Times(2)
		expectAppendControlFrames()
		expectAppendStreamFrames(&wire.StreamFrame{Data: []byte("foobar")})
		expectAppendControlFrames()
		expectAppendStreamFrames(&wire.StreamFrame{Data: []byte("raboof")})
		p1, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p1).ToNot(BeNil())
		p2, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p2).ToNot(BeNil())
		Expect(p2.header.PacketNumber).To(BeNumerically(">", p1.header.PacketNumber))
	})

	It("packs ACKs and STOP_WAITING frames first, then control frames, then STREAM frames", func() {
		sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
		cryptoStream.EXPECT().hasData()
		ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 100}}}
		swf := &wire.StopWaitingFrame{LeastUnacked: 10}
		mdf := &wire.MaxDataFrame{ByteOffset: 0x1234}
		sf := &wire.StreamFrame{Data: []byte("foobar")}
		ackFramer.EXPECT().GetAckFrame().Return(ack)
		ackFramer.EXPECT().GetStopWaitingFrame(false).Return(swf)
		expectAppendControlFrames(mdf)
		expectAppendStreamFrames(sf)
		packer.packetNumberGenerator.next = 15
		p, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
		Expect(p.frames).To(Equal([]wire.Frame{ack, swf, mdf, sf}))
	})

	It("sets the LeastUnackedDelta length of a STOP_WAITING frame", func() {
		sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
		cryptoStream.EXPECT().hasData()
		swf := &wire.StopWaitingFrame{LeastUnacked: 0x1337 - 0x100}
		ackFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 100}}})
		ackFramer.EXPECT().GetStopWaitingFrame(false).Return(swf)
		expectAppendControlFrames()
		expectAppendStreamFrames()
		packer.packetNumberGenerator.next = 0x1337
		p, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(HaveLen(2))
		Expect(p.frames[1].(*wire.StopWaitingFrame).PacketNumberLen).To(Equal(protocol.PacketNumberLen2))
	})

	It("refuses to send a packet that doesn't contain crypto stream data, if it has never sent a packet before", func() {
		cryptoStream.EXPECT().hasData()
		packer.hasSentPacket = false
		p, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p).To(BeNil())
	})

	It("accounts for the space consumed by control frames", func() {
		sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
		cryptoStream.EXPECT().hasData()
		ackFramer.EXPECT().GetAckFrame()
		var maxSize protocol.ByteCount
		gomock.InOrder(
			framer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(fs []wire.Frame, maxLen protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
				maxSize = maxLen
				return fs, 444
			}),
			framer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any()).Do(func(_ []wire.Frame, maxLen protocol.ByteCount) []wire.Frame {
				Expect(maxLen).To(Equal(maxSize - 444 + 2 /* data length of the STREAM frame */))
				return nil
			}),
		)
		_, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
	})

	It("only increases the packet number when there is an actual packet to send", func() {
		sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer).Times(2)
		ackFramer.EXPECT().GetAckFrame().Times(2)
		cryptoStream.EXPECT().hasData().Times(2)
		expectAppendStreamFrames()
		expectAppendControlFrames()
		packer.packetNumberGenerator.nextToSkip = 1000
		p, err := packer.PackPacket()
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(packer.packetNumberGenerator.Peek()).To(Equal(protocol.PacketNumber(1)))
		expectAppendControlFrames()
		expectAppendStreamFrames(&wire.StreamFrame{Data: []byte("foobar")})
		p, err = packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
		Expect(p.header.PacketNumber).To(Equal(protocol.PacketNumber(1)))
		Expect(packer.packetNumberGenerator.Peek()).To(Equal(protocol.PacketNumber(2)))
	})

	Context("making ACK packets retransmittable", func() {
		sendMaxNumNonRetransmittableAcks := func() {
			cryptoStream.EXPECT().hasData().Times(protocol.MaxNonRetransmittableAcks)
			for i := 0; i < protocol.MaxNonRetransmittableAcks; i++ {
				sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
				ackFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
				ackFramer.EXPECT().GetStopWaitingFrame(false)
				expectAppendControlFrames()
				expectAppendStreamFrames()
				p, err := packer.PackPacket()
				Expect(p).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(p.frames).To(HaveLen(1))
			}
		}

		It("adds a PING frame when it's supposed to send a retransmittable packet", func() {
			sendMaxNumNonRetransmittableAcks()
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			cryptoStream.EXPECT().hasData()
			ackFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
			ackFramer.EXPECT().GetStopWaitingFrame(false)
			expectAppendControlFrames()
			expectAppendStreamFrames()
			p, err := packer.PackPacket()
			Expect(p).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(ContainElement(&wire.PingFrame{}))
			// make sure the next packet doesn't contain another PING
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			cryptoStream.EXPECT().hasData()
			ackFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
			ackFramer.EXPECT().GetStopWaitingFrame(false)
			expectAppendControlFrames()
			expectAppendStreamFrames()
			p, err = packer.PackPacket()
			Expect(p).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(HaveLen(1))
		})

		It("waits until there's something to send before adding a PING frame", func() {
			sendMaxNumNonRetransmittableAcks()
			// nothing to send
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			cryptoStream.EXPECT().hasData()
			expectAppendControlFrames()
			expectAppendStreamFrames()
			ackFramer.EXPECT().GetAckFrame()
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(BeNil())
			// now add some frame to send
			expectAppendControlFrames()
			expectAppendStreamFrames()
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			cryptoStream.EXPECT().hasData()
			ackFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
			ackFramer.EXPECT().GetStopWaitingFrame(false)
			p, err = packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(HaveLen(2))
			Expect(p.frames).To(ContainElement(&wire.PingFrame{}))
		})

		It("doesn't send a PING if it already sent another retransmittable frame", func() {
			sendMaxNumNonRetransmittableAcks()
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			cryptoStream.EXPECT().hasData()
			ackFramer.EXPECT().GetAckFrame()
			expectAppendStreamFrames()
			expectAppendControlFrames(&wire.MaxDataFrame{})
			p, err := packer.PackPacket()
			Expect(p).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).ToNot(ContainElement(&wire.PingFrame{}))
		})
	})

	Context("STREAM frame handling", func() {
		It("does not split a STREAM frame with maximum size", func() {
			cryptoStream.EXPECT().hasData()
			ackFramer.EXPECT().GetAckFrame()
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			expectAppendControlFrames()
			sf := &wire.StreamFrame{
				Offset:         1,
				StreamID:       5,
				DataLenPresent: true,
			}
			framer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(_ []wire.Frame, maxSize protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
				sf.Data = bytes.Repeat([]byte{'f'}, int(maxSize-sf.Length(packer.version)))
				return []wire.Frame{sf}, sf.Length(packer.version)
			})
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(HaveLen(1))
			Expect(p.raw).To(HaveLen(int(maxPacketSize)))
			Expect(p.frames[0].(*wire.StreamFrame).Data).To(HaveLen(len(sf.Data)))
			Expect(p.frames[0].(*wire.StreamFrame).DataLenPresent).To(BeFalse())
		})

		It("packs multiple small STREAM frames into single packet", func() {
			f1 := &wire.StreamFrame{
				StreamID:       5,
				Data:           []byte("frame 1"),
				DataLenPresent: true,
			}
			f2 := &wire.StreamFrame{
				StreamID:       5,
				Data:           []byte("frame 2"),
				DataLenPresent: true,
			}
			f3 := &wire.StreamFrame{
				StreamID:       3,
				Data:           []byte("frame 3"),
				DataLenPresent: true,
			}
			cryptoStream.EXPECT().hasData()
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			ackFramer.EXPECT().GetAckFrame()
			expectAppendControlFrames()
			expectAppendStreamFrames(f1, f2, f3)
			p, err := packer.PackPacket()
			Expect(p).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(HaveLen(3))
			Expect(p.frames[0].(*wire.StreamFrame).Data).To(Equal([]byte("frame 1")))
			Expect(p.frames[0].(*wire.StreamFrame).DataLenPresent).To(BeTrue())
			Expect(p.frames[1].(*wire.StreamFrame).Data).To(Equal([]byte("frame 2")))
			Expect(p.frames[1].(*wire.StreamFrame).DataLenPresent).To(BeTrue())
			Expect(p.frames[2].(*wire.StreamFrame).Data).To(Equal([]byte("frame 3")))
			Expect(p.frames[2].(*wire.StreamFrame).DataLenPresent).To(BeFalse())
		})

		It("refuses to send unencrypted stream data on a data stream", func() {
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionUnencrypted, sealer)
			cryptoStream.EXPECT().hasData()
			ackFramer.EXPECT().GetAckFrame()
			expectAppendControlFrames()
			// don't expect a call to framer.PopStreamFrames
			p, err := packer.PackPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(p).To(BeNil())
		})

		It("sends non forward-secure data as the client", func() {
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionSecure, sealer)
			cryptoStream.EXPECT().hasData()
			ackFramer.EXPECT().GetAckFrame()
			expectAppendControlFrames()
			f := &wire.StreamFrame{
				StreamID: 5,
				Data:     []byte("foobar"),
			}
			expectAppendStreamFrames(f)
			packer.perspective = protocol.PerspectiveClient
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.encryptionLevel).To(Equal(protocol.EncryptionSecure))
			Expect(p.frames).To(Equal([]wire.Frame{f}))
		})

		It("does not send non forward-secure data as the server", func() {
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionSecure, sealer)
			cryptoStream.EXPECT().hasData()
			ackFramer.EXPECT().GetAckFrame()
			expectAppendControlFrames()
			// don't expect a call to framer.PopStreamFrames
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(BeNil())
		})

		It("sends unencrypted stream data on the crypto stream", func() {
			sealingManager.EXPECT().GetSealerForCryptoStream().Return(protocol.EncryptionUnencrypted, sealer)
			f := &wire.StreamFrame{
				StreamID: packer.version.CryptoStreamID(),
				Data:     []byte("foobar"),
			}
			cryptoStream.EXPECT().hasData().Return(true)
			cryptoStream.EXPECT().popStreamFrame(gomock.Any()).Return(f, false)
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(Equal([]wire.Frame{f}))
			Expect(p.encryptionLevel).To(Equal(protocol.EncryptionUnencrypted))
		})

		It("sends encrypted stream data on the crypto stream", func() {
			sealingManager.EXPECT().GetSealerForCryptoStream().Return(protocol.EncryptionSecure, sealer)
			f := &wire.StreamFrame{
				StreamID: packer.version.CryptoStreamID(),
				Data:     []byte("foobar"),
			}
			cryptoStream.EXPECT().hasData().Return(true)
			cryptoStream.EXPECT().popStreamFrame(gomock.Any()).Return(f, false)
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(Equal([]wire.Frame{f}))
			Expect(p.encryptionLevel).To(Equal(protocol.EncryptionSecure))
		})

		It("does not pack STREAM frames if not allowed", func() {
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionUnencrypted, sealer)
			cryptoStream.EXPECT().hasData()
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 10, Smallest: 1}}}
			ackFramer.EXPECT().GetAckFrame().Return(ack)
			ackFramer.EXPECT().GetStopWaitingFrame(false)
			expectAppendControlFrames()
			// don't expect a call to framer.PopStreamFrames
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(Equal([]wire.Frame{ack}))
		})
	})

	It("packs a single ACK", func() {
		cryptoStream.EXPECT().hasData()
		sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
		ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 42, Smallest: 1}}}
		ackFramer.EXPECT().GetAckFrame().Return(ack)
		ackFramer.EXPECT().GetStopWaitingFrame(false)
		expectAppendControlFrames()
		expectAppendStreamFrames()
		p, err := packer.PackPacket()
		Expect(err).NotTo(HaveOccurred())
		Expect(p).ToNot(BeNil())
		Expect(p.frames[0]).To(Equal(ack))
	})

	Context("retransmitting of handshake packets", func() {
		sf := &wire.StreamFrame{
			StreamID: 1,
			Data:     []byte("foobar"),
		}

		It("packs a retransmission with the right encryption level", func() {
			sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.EncryptionUnencrypted).Return(sealer, nil)
			swf := &wire.StopWaitingFrame{LeastUnacked: 1}
			ackFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
			packet := &ackhandler.Packet{
				PacketType:      protocol.PacketTypeHandshake,
				EncryptionLevel: protocol.EncryptionUnencrypted,
				Frames:          []wire.Frame{sf},
			}
			p, err := packer.PackRetransmission(packet)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(HaveLen(1))
			Expect(p[0].header.Type).To(Equal(protocol.PacketTypeHandshake))
			Expect(p[0].frames).To(Equal([]wire.Frame{swf, sf}))
			Expect(p[0].encryptionLevel).To(Equal(protocol.EncryptionUnencrypted))
		})

		It("packs a retransmission for a packet sent with secure encryption", func() {
			sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.EncryptionSecure).Return(sealer, nil)
			swf := &wire.StopWaitingFrame{LeastUnacked: 1}
			ackFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
			packet := &ackhandler.Packet{
				EncryptionLevel: protocol.EncryptionSecure,
				Frames:          []wire.Frame{sf},
			}
			p, err := packer.PackRetransmission(packet)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(HaveLen(1))
			Expect(p[0].frames).To(Equal([]wire.Frame{swf, sf}))
			Expect(p[0].encryptionLevel).To(Equal(protocol.EncryptionSecure))
			// a packet sent by the server with secure encryption contains the SHLO
			// it needs to have a diversification nonce
			Expect(p[0].raw).To(ContainSubstring(string(divNonce)))
		})

		// this should never happen, since non forward-secure packets are limited to a size smaller than MaxPacketSize, such that it is always possible to retransmit them without splitting the StreamFrame
		// (note that the retransmitted packet needs to have enough space for the StopWaitingFrame)
		It("refuses to send a packet larger than MaxPacketSize", func() {
			sealingManager.EXPECT().GetSealerWithEncryptionLevel(gomock.Any()).Return(sealer, nil)
			swf := &wire.StopWaitingFrame{LeastUnacked: 1}
			ackFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
			packet := &ackhandler.Packet{
				EncryptionLevel: protocol.EncryptionSecure,
				Frames: []wire.Frame{
					&wire.StreamFrame{
						StreamID: 1,
						Data:     bytes.Repeat([]byte{'f'}, int(maxPacketSize-5)),
					},
				},
			}
			_, err := packer.PackRetransmission(packet)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("PacketPacker BUG: packet too large"))
		})

		It("packs a retransmission for an Initial packet", func() {
			sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.EncryptionUnencrypted).Return(sealer, nil)
			packer.version = protocol.Version44
			packer.perspective = protocol.PerspectiveClient
			packet := &ackhandler.Packet{
				PacketType:      protocol.PacketTypeInitial,
				EncryptionLevel: protocol.EncryptionUnencrypted,
				Frames:          []wire.Frame{sf},
			}
			p, err := packer.PackRetransmission(packet)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(HaveLen(1))
			Expect(p[0].frames).To(Equal([]wire.Frame{sf}))
			Expect(p[0].encryptionLevel).To(Equal(protocol.EncryptionUnencrypted))
			Expect(p[0].header.Type).To(Equal(protocol.PacketTypeInitial))
		})
	})

	Context("retransmission of forward-secure packets", func() {
		It("retransmits a small packet", func() {
			swf := &wire.StopWaitingFrame{LeastUnacked: 7}
			packer.packetNumberGenerator.next = 10
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			ackFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
			frames := []wire.Frame{
				&wire.MaxDataFrame{ByteOffset: 0x1234},
				&wire.StreamFrame{StreamID: 42, Data: []byte("foobar")},
			}
			packets, err := packer.PackRetransmission(&ackhandler.Packet{
				EncryptionLevel: protocol.EncryptionForwardSecure,
				Frames:          frames,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(packets).To(HaveLen(1))
			p := packets[0]
			Expect(p.encryptionLevel).To(Equal(protocol.EncryptionForwardSecure))
			Expect(p.frames).To(HaveLen(3))
			Expect(p.frames[0]).To(BeAssignableToTypeOf(&wire.StopWaitingFrame{}))
			Expect(p.frames[0].(*wire.StopWaitingFrame).LeastUnacked).To(Equal(protocol.PacketNumber(7)))
			Expect(p.frames[0].(*wire.StopWaitingFrame).PacketNumber).To(Equal(p.header.PacketNumber))
			Expect(p.frames[0].(*wire.StopWaitingFrame).PacketNumberLen).To(Equal(p.header.PacketNumberLen))
			Expect(p.frames[1:]).To(Equal(frames))
		})

		It("packs two packets for retransmission if the original packet contained many control frames", func() {
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			var frames []wire.Frame
			var totalLen protocol.ByteCount
			// pack a bunch of control frames, such that the packet is way bigger than a single packet
			for i := 0; totalLen < maxPacketSize*3/2; i++ {
				f := &wire.MaxStreamDataFrame{
					StreamID:   protocol.StreamID(i),
					ByteOffset: protocol.ByteCount(i),
				}
				frames = append(frames, f)
				totalLen += f.Length(packer.version)
			}
			packer.packetNumberGenerator.next = 10
			swf := &wire.StopWaitingFrame{LeastUnacked: 7}
			ackFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
			packets, err := packer.PackRetransmission(&ackhandler.Packet{
				EncryptionLevel: protocol.EncryptionForwardSecure,
				Frames:          frames,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(packets).To(HaveLen(2))
			Expect(len(packets[0].frames) + len(packets[1].frames)).To(Equal(len(frames) + 2)) // all frames, plus 2 STOP_WAITING frames
			Expect(packets[0].frames[0]).To(BeAssignableToTypeOf(&wire.StopWaitingFrame{}))
			Expect(packets[1].frames[0]).To(BeAssignableToTypeOf(&wire.StopWaitingFrame{}))
			Expect(packets[0].frames[1:]).To(Equal(frames[:len(packets[0].frames)-1]))
			Expect(packets[1].frames[1:]).To(Equal(frames[len(packets[0].frames)-1:]))
			// check that the first packet was filled up as far as possible:
			// if the first frame (after the STOP_WAITING) was packed into the first packet, it would have overflown the MaxPacketSize
			Expect(len(packets[0].raw) + int(packets[1].frames[1].Length(packer.version))).To(BeNumerically(">", maxPacketSize))
		})

		It("splits a STREAM frame that doesn't fit", func() {
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			swf := &wire.StopWaitingFrame{}
			ackFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
			packets, err := packer.PackRetransmission(&ackhandler.Packet{
				EncryptionLevel: protocol.EncryptionForwardSecure,
				Frames: []wire.Frame{&wire.StreamFrame{
					StreamID: 42,
					Offset:   1337,
					Data:     bytes.Repeat([]byte{'a'}, int(maxPacketSize)*3/2),
				}},
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(packets).To(HaveLen(2))
			Expect(packets[0].frames[0]).To(BeAssignableToTypeOf(&wire.StopWaitingFrame{}))
			Expect(packets[1].frames[0]).To(BeAssignableToTypeOf(&wire.StopWaitingFrame{}))
			Expect(packets[0].frames[1]).To(BeAssignableToTypeOf(&wire.StreamFrame{}))
			Expect(packets[1].frames[1]).To(BeAssignableToTypeOf(&wire.StreamFrame{}))
			sf1 := packets[0].frames[1].(*wire.StreamFrame)
			sf2 := packets[1].frames[1].(*wire.StreamFrame)
			Expect(sf1.StreamID).To(Equal(protocol.StreamID(42)))
			Expect(sf1.Offset).To(Equal(protocol.ByteCount(1337)))
			Expect(sf1.DataLenPresent).To(BeFalse())
			Expect(sf2.StreamID).To(Equal(protocol.StreamID(42)))
			Expect(sf2.Offset).To(Equal(protocol.ByteCount(1337) + sf1.DataLen()))
			Expect(sf2.DataLenPresent).To(BeFalse())
			Expect(sf1.DataLen() + sf2.DataLen()).To(Equal(maxPacketSize * 3 / 2))
			Expect(packets[0].raw).To(HaveLen(int(maxPacketSize)))
		})

		It("splits STREAM frames, if necessary", func() {
			for i := 0; i < 100; i++ {
				sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer).MaxTimes(2)
				swf := &wire.StopWaitingFrame{}
				ackFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
				sf1 := &wire.StreamFrame{
					StreamID: 42,
					Offset:   1337,
					Data:     bytes.Repeat([]byte{'a'}, 1+int(rand.Int31n(int32(maxPacketSize*4/5)))),
				}
				sf2 := &wire.StreamFrame{
					StreamID: 2,
					Offset:   42,
					Data:     bytes.Repeat([]byte{'b'}, 1+int(rand.Int31n(int32(maxPacketSize*4/5)))),
				}
				expectedDataLen := sf1.DataLen() + sf2.DataLen()
				fmt.Fprintf(GinkgoWriter, "STREAM frame 1: %d bytes, STREAM frame 2: %d\n", sf1.DataLen(), sf2.DataLen())
				frames := []wire.Frame{sf1, sf2}
				packets, err := packer.PackRetransmission(&ackhandler.Packet{
					EncryptionLevel: protocol.EncryptionForwardSecure,
					Frames:          frames,
				})
				Expect(err).ToNot(HaveOccurred())

				if len(packets) > 1 {
					Expect(packets[0].raw).To(HaveLen(int(maxPacketSize)))
				}

				var dataLen protocol.ByteCount
				for _, p := range packets {
					for _, f := range p.frames {
						if sf, ok := f.(*wire.StreamFrame); ok {
							dataLen += sf.DataLen()
						}
					}
				}
				Expect(dataLen).To(Equal(expectedDataLen))
			}
		})

		It("packs two packets for retransmission if the original packet contained many STREAM frames", func() {
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			swf := &wire.StopWaitingFrame{}
			ackFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
			var frames []wire.Frame
			var totalLen protocol.ByteCount
			// pack a bunch of control frames, such that the packet is way bigger than a single packet
			for i := 0; totalLen < maxPacketSize*3/2; i++ {
				f := &wire.StreamFrame{
					StreamID:       protocol.StreamID(i),
					Data:           []byte("foobar"),
					DataLenPresent: true,
				}
				frames = append(frames, f)
				totalLen += f.Length(packer.version)
			}
			packets, err := packer.PackRetransmission(&ackhandler.Packet{
				EncryptionLevel: protocol.EncryptionForwardSecure,
				Frames:          frames,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(packets).To(HaveLen(2))
			Expect(len(packets[0].frames) + len(packets[1].frames)).To(Equal(len(frames) + 2)) // all frames, plus 2 STOP_WAITING frames
			Expect(packets[0].frames[0]).To(BeAssignableToTypeOf(&wire.StopWaitingFrame{}))
			Expect(packets[1].frames[0]).To(BeAssignableToTypeOf(&wire.StopWaitingFrame{}))
			Expect(packets[0].frames[1:]).To(Equal(frames[:len(packets[0].frames)-1]))
			Expect(packets[1].frames[1:]).To(Equal(frames[len(packets[0].frames)-1:]))
			// check that the first packet was filled up as far as possible:
			// if the first frame (after the STOP_WAITING) was packed into the first packet, it would have overflown the MaxPacketSize
			Expect(len(packets[0].raw) + int(packets[1].frames[1].Length(packer.version))).To(BeNumerically(">", maxPacketSize-protocol.MinStreamFrameSize))
		})

		It("correctly sets the DataLenPresent on STREAM frames", func() {
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			swf := &wire.StopWaitingFrame{}
			ackFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
			frames := []wire.Frame{
				&wire.StreamFrame{StreamID: 4, Data: []byte("foobar"), DataLenPresent: true},
				&wire.StreamFrame{StreamID: 5, Data: []byte("barfoo")},
			}
			packets, err := packer.PackRetransmission(&ackhandler.Packet{
				EncryptionLevel: protocol.EncryptionForwardSecure,
				Frames:          frames,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(packets).To(HaveLen(1))
			p := packets[0]
			Expect(p.frames).To(HaveLen(3))
			Expect(p.frames[1]).To(BeAssignableToTypeOf(&wire.StreamFrame{}))
			Expect(p.frames[2]).To(BeAssignableToTypeOf(&wire.StreamFrame{}))
			sf1 := p.frames[1].(*wire.StreamFrame)
			sf2 := p.frames[2].(*wire.StreamFrame)
			Expect(sf1.StreamID).To(Equal(protocol.StreamID(4)))
			Expect(sf1.DataLenPresent).To(BeTrue())
			Expect(sf2.StreamID).To(Equal(protocol.StreamID(5)))
			Expect(sf2.DataLenPresent).To(BeFalse())
		})
	})

	Context("packing ACK packets", func() {
		It("doesn't pack a packet if there's no ACK to send", func() {
			ackFramer.EXPECT().GetAckFrame()
			p, err := packer.MaybePackAckPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(BeNil())
		})

		It("packs ACK packets", func() {
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
			swf := &wire.StopWaitingFrame{}
			ackFramer.EXPECT().GetAckFrame().Return(ack)
			ackFramer.EXPECT().GetStopWaitingFrame(false).Return(swf)
			p, err := packer.MaybePackAckPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(p.frames).To(Equal([]wire.Frame{ack, swf}))
		})

		It("doesn't add a STOP_WAITING frame, for gQUIC 44", func() {
			sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionForwardSecure, sealer)
			packer.version = protocol.Version44
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
			ackFramer.EXPECT().GetAckFrame().Return(ack)
			p, err := packer.MaybePackAckPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(p.frames).To(Equal([]wire.Frame{ack}))
		})
	})
})
