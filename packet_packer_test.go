package quic

import (
	"bytes"
	"net"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockSealer struct{}

func (s *mockSealer) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	return append(src, bytes.Repeat([]byte{0}, 12)...)
}

func (s *mockSealer) Overhead() int { return 12 }

var _ handshake.Sealer = &mockSealer{}

type mockCryptoSetup struct {
	handleErr          error
	encLevelSeal       protocol.EncryptionLevel
	encLevelSealCrypto protocol.EncryptionLevel
	divNonce           []byte
}

var _ handshake.CryptoSetup = &mockCryptoSetup{}

func (m *mockCryptoSetup) HandleCryptoStream() error {
	return m.handleErr
}
func (m *mockCryptoSetup) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error) {
	return nil, protocol.EncryptionUnspecified, nil
}
func (m *mockCryptoSetup) GetSealer() (protocol.EncryptionLevel, handshake.Sealer) {
	return m.encLevelSeal, &mockSealer{}
}
func (m *mockCryptoSetup) GetSealerForCryptoStream() (protocol.EncryptionLevel, handshake.Sealer) {
	return m.encLevelSealCrypto, &mockSealer{}
}
func (m *mockCryptoSetup) GetSealerWithEncryptionLevel(protocol.EncryptionLevel) (handshake.Sealer, error) {
	return &mockSealer{}, nil
}
func (m *mockCryptoSetup) SetDiversificationNonce(divNonce []byte) error {
	m.divNonce = divNonce
	return nil
}
func (m *mockCryptoSetup) ConnectionState() ConnectionState { panic("not implemented") }

var _ = Describe("Packet packer", func() {
	const maxPacketSize protocol.ByteCount = 1357
	var (
		packer        *packetPacker
		mockFramer    *MockFrameSource
		mockAckFramer *MockAckFrameSource
		divNonce      []byte
		token         []byte
	)

	checkPayloadLen := func(data []byte) {
		r := bytes.NewReader(data)
		iHdr, err := wire.ParseInvariantHeader(r, 0)
		Expect(err).ToNot(HaveOccurred())
		hdr, err := iHdr.Parse(r, protocol.PerspectiveServer, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		ExpectWithOffset(0, hdr.PayloadLen).To(BeEquivalentTo(r.Len()))
	}

	expectAppendStreamFrames := func(frames ...wire.Frame) {
		mockFramer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(fs []wire.Frame, _ protocol.ByteCount) []wire.Frame {
			return append(fs, frames...)
		})
	}

	expectAppendControlFrames := func(frames ...wire.Frame) {
		mockFramer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(fs []wire.Frame, _ protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
			var length protocol.ByteCount
			for _, f := range frames {
				length += f.Length(packer.version)
			}
			return append(fs, frames...), length
		})
	}

	BeforeEach(func() {
		version := versionGQUICFrames
		mockSender := NewMockStreamSender(mockCtrl)
		mockSender.EXPECT().onHasStreamData(gomock.Any()).AnyTimes()
		mockFramer = NewMockFrameSource(mockCtrl)
		mockAckFramer = NewMockAckFrameSource(mockCtrl)
		divNonce = bytes.Repeat([]byte{'e'}, 32)
		token = []byte("initial token")

		packer = newPacketPacker(
			protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			1,
			func(protocol.PacketNumber) protocol.PacketNumberLen { return protocol.PacketNumberLen2 },
			&net.TCPAddr{},
			token, // token
			divNonce,
			&mockCryptoSetup{encLevelSeal: protocol.EncryptionForwardSecure},
			mockFramer,
			mockAckFramer,
			protocol.PerspectiveServer,
			version,
		)
		packer.hasSentPacket = true
		packer.version = version
		packer.maxPacketSize = maxPacketSize
	})

	Context("determining the maximum packet size", func() {
		It("uses the minimum initial size, if it can't determine if the remote address is IPv4 or IPv6", func() {
			Expect(getMaxPacketSize(&net.TCPAddr{})).To(BeEquivalentTo(protocol.MinInitialPacketSize))
		})

		It("uses the maximum IPv4 packet size, if the remote address is IPv4", func() {
			addr := &net.UDPAddr{IP: net.IPv4(11, 12, 13, 14), Port: 1337}
			Expect(getMaxPacketSize(addr)).To(BeEquivalentTo(protocol.MaxPacketSizeIPv4))
		})

		It("uses the maximum IPv6 packet size, if the remote address is IPv6", func() {
			ip := net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
			addr := &net.UDPAddr{IP: ip, Port: 1337}
			Expect(getMaxPacketSize(addr)).To(BeEquivalentTo(protocol.MaxPacketSizeIPv6))
		})
	})

	It("returns nil when no packet is queued", func() {
		mockAckFramer.EXPECT().GetAckFrame()
		mockFramer.EXPECT().HasCryptoStreamData()
		mockFramer.EXPECT().AppendControlFrames(nil, gomock.Any())
		mockFramer.EXPECT().AppendStreamFrames(nil, gomock.Any())
		p, err := packer.PackPacket()
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
	})

	It("packs single packets", func() {
		mockFramer.EXPECT().HasCryptoStreamData()
		mockAckFramer.EXPECT().GetAckFrame()
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
		mockFramer.EXPECT().HasCryptoStreamData()
		mockAckFramer.EXPECT().GetAckFrame()
		expectAppendControlFrames()
		expectAppendStreamFrames(&wire.StreamFrame{
			StreamID: 5,
			Data:     []byte("foobar"),
		})
		packer.cryptoSetup.(*mockCryptoSetup).encLevelSeal = protocol.EncryptionForwardSecure
		p, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p.encryptionLevel).To(Equal(protocol.EncryptionForwardSecure))
	})

	Context("generating a packet header", func() {
		const (
			versionPublicHeader = protocol.Version39  // a QUIC version that uses the Public Header format
			versionIETFHeader   = protocol.VersionTLS // a QUIC version that uses the IETF Header format
		)

		Context("Public Header (for gQUIC)", func() {
			BeforeEach(func() {
				packer.version = versionPublicHeader
			})

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

		Context("Header (for IETF draft QUIC)", func() {
			BeforeEach(func() {
				packer.version = versionIETFHeader
			})

			It("uses the Long Header format for non-forward-secure packets", func() {
				h := packer.getHeader(protocol.EncryptionSecure)
				Expect(h.IsLongHeader).To(BeTrue())
				Expect(h.Version).To(Equal(versionIETFHeader))
			})

			It("sets source and destination connection ID", func() {
				srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				destConnID := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
				packer.srcConnID = srcConnID
				packer.destConnID = destConnID
				h := packer.getHeader(protocol.EncryptionSecure)
				Expect(h.SrcConnectionID).To(Equal(srcConnID))
				Expect(h.DestConnectionID).To(Equal(destConnID))
			})

			It("changes the destination connection ID", func() {
				srcConnID := protocol.ConnectionID{1, 1, 1, 1, 1, 1, 1, 1}
				packer.srcConnID = srcConnID
				dest1 := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				dest2 := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
				packer.ChangeDestConnectionID(dest1)
				h := packer.getHeader(protocol.EncryptionUnencrypted)
				Expect(h.SrcConnectionID).To(Equal(srcConnID))
				Expect(h.DestConnectionID).To(Equal(dest1))
				packer.ChangeDestConnectionID(dest2)
				h = packer.getHeader(protocol.EncryptionUnencrypted)
				Expect(h.SrcConnectionID).To(Equal(srcConnID))
				Expect(h.DestConnectionID).To(Equal(dest2))
			})

			It("uses the Short Header format for forward-secure packets", func() {
				h := packer.getHeader(protocol.EncryptionForwardSecure)
				Expect(h.IsLongHeader).To(BeFalse())
				Expect(h.PacketNumberLen).To(BeNumerically(">", 0))
			})
		})
	})

	It("sets the payload length for packets containing crypto data", func() {
		packer.version = versionIETFFrames
		f := &wire.StreamFrame{
			StreamID: packer.version.CryptoStreamID(),
			Offset:   0x1337,
			Data:     []byte("foobar"),
		}
		mockFramer.EXPECT().HasCryptoStreamData().Return(true)
		mockFramer.EXPECT().PopCryptoStreamFrame(gomock.Any()).Return(f)
		p, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		checkPayloadLen(p.raw)
	})

	It("packs a CONNECTION_CLOSE", func() {
		ccf := wire.ConnectionCloseFrame{
			ErrorCode:    0x1337,
			ReasonPhrase: "foobar",
		}
		p, err := packer.PackConnectionClose(&ccf)
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(HaveLen(1))
		Expect(p.frames[0]).To(Equal(&ccf))
	})

	It("doesn't send any other frames when sending a CONNECTION_CLOSE", func() {
		// expect no mockFramer.PopStreamFrames
		ccf := &wire.ConnectionCloseFrame{
			ErrorCode:    0x1337,
			ReasonPhrase: "foobar",
		}
		p, err := packer.PackConnectionClose(ccf)
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(Equal([]wire.Frame{ccf}))
	})

	It("packs control frames", func() {
		mockFramer.EXPECT().HasCryptoStreamData()
		mockAckFramer.EXPECT().GetAckFrame()
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
		mockFramer.EXPECT().HasCryptoStreamData().Times(2)
		mockAckFramer.EXPECT().GetAckFrame().Times(2)
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
		mockFramer.EXPECT().HasCryptoStreamData()
		ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 100}}}
		swf := &wire.StopWaitingFrame{LeastUnacked: 10}
		mdf := &wire.MaxDataFrame{ByteOffset: 0x1234}
		sf := &wire.StreamFrame{Data: []byte("foobar")}
		mockAckFramer.EXPECT().GetAckFrame().Return(ack)
		mockAckFramer.EXPECT().GetStopWaitingFrame(false).Return(swf)
		expectAppendControlFrames(mdf)
		expectAppendStreamFrames(sf)
		packer.packetNumberGenerator.next = 15
		p, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p).ToNot(BeNil())
		Expect(p.frames).To(Equal([]wire.Frame{ack, swf, mdf, sf}))
	})

	It("sets the LeastUnackedDelta length of a STOP_WAITING frame", func() {
		mockFramer.EXPECT().HasCryptoStreamData()
		swf := &wire.StopWaitingFrame{LeastUnacked: 0x1337 - 0x100}
		mockAckFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 100}}})
		mockAckFramer.EXPECT().GetStopWaitingFrame(false).Return(swf)
		expectAppendControlFrames()
		expectAppendStreamFrames()
		packer.packetNumberGenerator.next = 0x1337
		p, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p.frames).To(HaveLen(2))
		Expect(p.frames[1].(*wire.StopWaitingFrame).PacketNumberLen).To(Equal(protocol.PacketNumberLen2))
	})

	It("refuses to send a packet that doesn't contain crypto stream data, if it has never sent a packet before", func() {
		mockFramer.EXPECT().HasCryptoStreamData()
		packer.hasSentPacket = false
		p, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p).To(BeNil())
	})

	It("accounts for the space consumed by control frames", func() {
		mockFramer.EXPECT().HasCryptoStreamData()
		mockAckFramer.EXPECT().GetAckFrame()
		var maxSize protocol.ByteCount
		gomock.InOrder(
			mockFramer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(fs []wire.Frame, maxLen protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
				maxSize = maxLen
				return fs, 444
			}),
			mockFramer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any()).Do(func(_ []wire.Frame, maxLen protocol.ByteCount) []wire.Frame {
				Expect(maxLen).To(Equal(maxSize - 444 + 2 /* data length of the STREAM frame */))
				return nil
			}),
		)
		_, err := packer.PackPacket()
		Expect(err).ToNot(HaveOccurred())
	})

	It("only increases the packet number when there is an actual packet to send", func() {
		mockAckFramer.EXPECT().GetAckFrame().Times(2)
		mockFramer.EXPECT().HasCryptoStreamData().Times(2)
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
			mockFramer.EXPECT().HasCryptoStreamData().Times(protocol.MaxNonRetransmittableAcks)
			for i := 0; i < protocol.MaxNonRetransmittableAcks; i++ {
				mockAckFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
				mockAckFramer.EXPECT().GetStopWaitingFrame(false)
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
			mockFramer.EXPECT().HasCryptoStreamData()
			mockAckFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
			mockAckFramer.EXPECT().GetStopWaitingFrame(false)
			expectAppendControlFrames()
			expectAppendStreamFrames()
			p, err := packer.PackPacket()
			Expect(p).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(ContainElement(&wire.PingFrame{}))
			// make sure the next packet doesn't contain another PING
			mockFramer.EXPECT().HasCryptoStreamData()
			mockAckFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
			mockAckFramer.EXPECT().GetStopWaitingFrame(false)
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
			mockFramer.EXPECT().HasCryptoStreamData()
			expectAppendControlFrames()
			expectAppendStreamFrames()
			mockAckFramer.EXPECT().GetAckFrame()
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(BeNil())
			// now add some frame to send
			expectAppendControlFrames()
			expectAppendStreamFrames()
			mockFramer.EXPECT().HasCryptoStreamData()
			mockAckFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
			mockAckFramer.EXPECT().GetStopWaitingFrame(false)
			p, err = packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(HaveLen(2))
			Expect(p.frames).To(ContainElement(&wire.PingFrame{}))
		})

		It("doesn't send a PING if it already sent another retransmittable frame", func() {
			sendMaxNumNonRetransmittableAcks()
			mockFramer.EXPECT().HasCryptoStreamData()
			mockAckFramer.EXPECT().GetAckFrame()
			expectAppendStreamFrames()
			expectAppendControlFrames(&wire.MaxDataFrame{})
			p, err := packer.PackPacket()
			Expect(p).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).ToNot(ContainElement(&wire.PingFrame{}))
		})
	})

	Context("STREAM frame handling", func() {
		It("does not split a STREAM frame with maximum size, for gQUIC frames", func() {
			mockFramer.EXPECT().HasCryptoStreamData()
			mockAckFramer.EXPECT().GetAckFrame()
			expectAppendControlFrames()
			sf := &wire.StreamFrame{
				Offset:         1,
				StreamID:       5,
				DataLenPresent: true,
			}
			mockFramer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(_ []wire.Frame, maxSize protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
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

		It("does not split a STREAM frame with maximum size, for IETF draft style frame", func() {
			packer.version = versionIETFFrames
			mockAckFramer.EXPECT().GetAckFrame()
			mockFramer.EXPECT().HasCryptoStreamData()
			expectAppendControlFrames()
			sf := &wire.StreamFrame{
				Offset:         1,
				StreamID:       5,
				DataLenPresent: true,
			}
			mockFramer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(_ []wire.Frame, maxSize protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
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
			mockFramer.EXPECT().HasCryptoStreamData()
			mockAckFramer.EXPECT().GetAckFrame()
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
			mockFramer.EXPECT().HasCryptoStreamData()
			mockAckFramer.EXPECT().GetAckFrame()
			expectAppendControlFrames()
			// don't expect a call to mockFramer.PopStreamFrames
			packer.cryptoSetup.(*mockCryptoSetup).encLevelSeal = protocol.EncryptionUnencrypted
			p, err := packer.PackPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(p).To(BeNil())
		})

		It("sends non forward-secure data as the client", func() {
			mockFramer.EXPECT().HasCryptoStreamData()
			mockAckFramer.EXPECT().GetAckFrame()
			expectAppendControlFrames()
			f := &wire.StreamFrame{
				StreamID: 5,
				Data:     []byte("foobar"),
			}
			expectAppendStreamFrames(f)
			packer.perspective = protocol.PerspectiveClient
			packer.cryptoSetup.(*mockCryptoSetup).encLevelSeal = protocol.EncryptionSecure
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.encryptionLevel).To(Equal(protocol.EncryptionSecure))
			Expect(p.frames).To(Equal([]wire.Frame{f}))
		})

		It("does not send non forward-secure data as the server", func() {
			mockFramer.EXPECT().HasCryptoStreamData()
			mockAckFramer.EXPECT().GetAckFrame()
			expectAppendControlFrames()
			// don't expect a call to mockFramer.PopStreamFrames
			packer.cryptoSetup.(*mockCryptoSetup).encLevelSeal = protocol.EncryptionSecure
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(BeNil())
		})

		It("packs a maximum size crypto packet", func() {
			var f *wire.StreamFrame
			packer.version = versionIETFFrames
			mockFramer.EXPECT().HasCryptoStreamData().Return(true)
			mockFramer.EXPECT().PopCryptoStreamFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) *wire.StreamFrame {
				f = &wire.StreamFrame{
					StreamID: packer.version.CryptoStreamID(),
					Offset:   0x1337,
				}
				f.Data = bytes.Repeat([]byte{'f'}, int(size-f.Length(packer.version)))
				return f
			})
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(HaveLen(1))
			expectedPacketLen := packer.maxPacketSize - protocol.NonForwardSecurePacketSizeReduction
			Expect(p.raw).To(HaveLen(int(expectedPacketLen)))
			Expect(p.header.IsLongHeader).To(BeTrue())
			checkPayloadLen(p.raw)
		})

		It("sends unencrypted stream data on the crypto stream", func() {
			f := &wire.StreamFrame{
				StreamID: packer.version.CryptoStreamID(),
				Data:     []byte("foobar"),
			}
			mockFramer.EXPECT().HasCryptoStreamData().Return(true)
			mockFramer.EXPECT().PopCryptoStreamFrame(gomock.Any()).Return(f)
			packer.cryptoSetup.(*mockCryptoSetup).encLevelSealCrypto = protocol.EncryptionUnencrypted
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(Equal([]wire.Frame{f}))
			Expect(p.encryptionLevel).To(Equal(protocol.EncryptionUnencrypted))
		})

		It("sends encrypted stream data on the crypto stream", func() {
			f := &wire.StreamFrame{
				StreamID: packer.version.CryptoStreamID(),
				Data:     []byte("foobar"),
			}
			mockFramer.EXPECT().HasCryptoStreamData().Return(true)
			mockFramer.EXPECT().PopCryptoStreamFrame(gomock.Any()).Return(f)
			packer.cryptoSetup.(*mockCryptoSetup).encLevelSealCrypto = protocol.EncryptionSecure
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(Equal([]wire.Frame{f}))
			Expect(p.encryptionLevel).To(Equal(protocol.EncryptionSecure))
		})

		It("does not pack STREAM frames if not allowed", func() {
			mockFramer.EXPECT().HasCryptoStreamData()
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 10, Smallest: 1}}}
			mockAckFramer.EXPECT().GetAckFrame().Return(ack)
			mockAckFramer.EXPECT().GetStopWaitingFrame(false)
			expectAppendControlFrames()
			// don't expect a call to mockFramer.PopStreamFrames
			packer.cryptoSetup.(*mockCryptoSetup).encLevelSeal = protocol.EncryptionUnencrypted
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(Equal([]wire.Frame{ack}))
		})
	})

	It("packs a single ACK", func() {
		mockFramer.EXPECT().HasCryptoStreamData()
		ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 42, Smallest: 1}}}
		mockAckFramer.EXPECT().GetAckFrame().Return(ack)
		mockAckFramer.EXPECT().GetStopWaitingFrame(false)
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

		It("packs a retransmission for a packet sent with no encryption", func() {
			swf := &wire.StopWaitingFrame{LeastUnacked: 1}
			mockAckFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
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

		It("doesn't add a STOP_WAITING frame for IETF QUIC", func() {
			packer.version = versionIETFFrames
			packet := &ackhandler.Packet{
				EncryptionLevel: protocol.EncryptionUnencrypted,
				Frames:          []wire.Frame{sf},
			}
			p, err := packer.PackRetransmission(packet)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(HaveLen(1))
			Expect(p[0].frames).To(Equal([]wire.Frame{sf}))
			Expect(p[0].encryptionLevel).To(Equal(protocol.EncryptionUnencrypted))
		})

		It("packs a retransmission for a packet sent with secure encryption", func() {
			swf := &wire.StopWaitingFrame{LeastUnacked: 1}
			mockAckFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
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
			swf := &wire.StopWaitingFrame{LeastUnacked: 1}
			mockAckFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
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

		It("pads Initial packets to the required minimum packet size", func() {
			f := &wire.StreamFrame{
				StreamID: packer.version.CryptoStreamID(),
				Data:     []byte("foobar"),
			}
			mockFramer.EXPECT().HasCryptoStreamData().Return(true)
			mockFramer.EXPECT().PopCryptoStreamFrame(gomock.Any()).Return(f)
			packer.version = protocol.VersionTLS
			packer.hasSentPacket = false
			packer.perspective = protocol.PerspectiveClient
			packer.cryptoSetup.(*mockCryptoSetup).encLevelSealCrypto = protocol.EncryptionUnencrypted
			packet, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.header.Token).To(Equal(token))
			Expect(packet.raw).To(HaveLen(protocol.MinInitialPacketSize))
			Expect(packet.frames).To(HaveLen(1))
			sf := packet.frames[0].(*wire.StreamFrame)
			Expect(sf.Data).To(Equal([]byte("foobar")))
			Expect(sf.DataLenPresent).To(BeTrue())
		})

		It("set the correct payload length for an Initial packet", func() {
			mockFramer.EXPECT().HasCryptoStreamData().Return(true)
			mockFramer.EXPECT().PopCryptoStreamFrame(gomock.Any()).Return(&wire.StreamFrame{
				StreamID: packer.version.CryptoStreamID(),
				Data:     []byte("foobar"),
			})
			packer.version = protocol.VersionTLS
			packer.hasSentPacket = false
			packer.perspective = protocol.PerspectiveClient
			packer.cryptoSetup.(*mockCryptoSetup).encLevelSealCrypto = protocol.EncryptionUnencrypted
			packet, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			checkPayloadLen(packet.raw)
		})

		It("packs a retransmission for an Initial packet", func() {
			packer.version = versionIETFFrames
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
			Expect(p[0].header.Token).To(Equal(token))
		})
	})

	Context("retransmission of forward-secure packets", func() {
		It("retransmits a small packet", func() {
			swf := &wire.StopWaitingFrame{LeastUnacked: 7}
			packer.packetNumberGenerator.next = 10
			mockAckFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
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
			var frames []wire.Frame
			var totalLen protocol.ByteCount
			// pack a bunch of control frames, such that the packet is way bigger than a single packet
			for i := 0; totalLen < maxPacketSize*3/2; i++ {
				f := &wire.MaxStreamDataFrame{StreamID: protocol.StreamID(i), ByteOffset: protocol.ByteCount(i)}
				frames = append(frames, f)
				totalLen += f.Length(packer.version)
			}
			packer.packetNumberGenerator.next = 10
			swf := &wire.StopWaitingFrame{LeastUnacked: 7}
			mockAckFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
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
			swf := &wire.StopWaitingFrame{}
			mockAckFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
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

		It("packs two packets for retransmission if the original packet contained many STREAM frames", func() {
			swf := &wire.StopWaitingFrame{}
			mockAckFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
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
			swf := &wire.StopWaitingFrame{}
			mockAckFramer.EXPECT().GetStopWaitingFrame(true).Return(swf)
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
			mockAckFramer.EXPECT().GetAckFrame()
			p, err := packer.MaybePackAckPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(BeNil())
		})

		It("packs ACK packets", func() {
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
			swf := &wire.StopWaitingFrame{}
			mockAckFramer.EXPECT().GetAckFrame().Return(ack)
			mockAckFramer.EXPECT().GetStopWaitingFrame(false).Return(swf)
			p, err := packer.MaybePackAckPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(p.frames).To(Equal([]wire.Frame{ack, swf}))
		})

		It("doesn't add a STOP_WAITING frame for IETF QUIC", func() {
			packer.version = versionIETFFrames
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
			mockAckFramer.EXPECT().GetAckFrame().Return(ack)
			p, err := packer.MaybePackAckPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(p.frames).To(Equal([]wire.Frame{ack}))
		})
	})

	Context("max packet size", func() {
		It("sets the maximum packet size", func() {
			mockAckFramer.EXPECT().GetAckFrame().Times(2)
			mockFramer.EXPECT().HasCryptoStreamData().AnyTimes()
			var initialMaxPacketSize protocol.ByteCount
			mockFramer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).Do(func(_ []wire.Frame, maxLen protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
				initialMaxPacketSize = maxLen
				return nil, 0
			})
			expectAppendStreamFrames()
			_, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			// now reduce the maxPacketSize
			packer.HandleTransportParameters(&handshake.TransportParameters{
				MaxPacketSize: maxPacketSize - 10,
			})
			mockFramer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).Do(func(_ []wire.Frame, maxLen protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
				Expect(maxLen).To(Equal(initialMaxPacketSize - 10))
				return nil, 0
			})
			expectAppendStreamFrames()
			_, err = packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
		})

		It("doesn't increase the max packet size", func() {
			mockAckFramer.EXPECT().GetAckFrame().Times(2)
			mockFramer.EXPECT().HasCryptoStreamData().AnyTimes()
			var initialMaxPacketSize protocol.ByteCount
			mockFramer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).Do(func(_ []wire.Frame, maxLen protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
				initialMaxPacketSize = maxLen
				return nil, 0
			})
			expectAppendStreamFrames()
			_, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			// now try to increase the maxPacketSize
			packer.HandleTransportParameters(&handshake.TransportParameters{
				MaxPacketSize: maxPacketSize + 10,
			})
			mockFramer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).Do(func(_ []wire.Frame, maxLen protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
				Expect(maxLen).To(Equal(initialMaxPacketSize))
				return nil, 0
			})
			expectAppendStreamFrames()
			_, err = packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
