package quic

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/mocks"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet packer", func() {
	const maxPacketSize protocol.ByteCount = 1357
	const version = protocol.Version1

	var (
		packer              *packetPacker
		retransmissionQueue *retransmissionQueue
		datagramQueue       *datagramQueue
		framer              *MockFrameSource
		ackFramer           *MockAckFrameSource
		initialStream       *MockCryptoStream
		handshakeStream     *MockCryptoStream
		sealingManager      *MockSealingManager
		pnManager           *mockackhandler.MockSentPacketHandler
	)
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})

	parsePacket := func(data []byte) (hdrs []*wire.ExtendedHeader, more []byte) {
		for len(data) > 0 {
			if !wire.IsLongHeaderPacket(data[0]) {
				break
			}
			hdr, _, more, err := wire.ParsePacket(data)
			Expect(err).ToNot(HaveOccurred())
			r := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(r, version)
			Expect(err).ToNot(HaveOccurred())
			ExpectWithOffset(1, extHdr.Length).To(BeEquivalentTo(r.Len() - len(more) + int(extHdr.PacketNumberLen)))
			ExpectWithOffset(1, extHdr.Length+protocol.ByteCount(extHdr.PacketNumberLen)).To(BeNumerically(">=", 4))
			data = more
			hdrs = append(hdrs, extHdr)
		}
		return hdrs, data
	}

	parseShortHeaderPacket := func(data []byte) {
		l, _, pnLen, _, err := wire.ParseShortHeader(data, connID.Len())
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		ExpectWithOffset(1, len(data)-l+int(pnLen)).To(BeNumerically(">=", 4))
	}

	expectAppendStreamFrames := func(frames ...ackhandler.StreamFrame) {
		framer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(fs []ackhandler.StreamFrame, _ protocol.ByteCount, v protocol.VersionNumber) ([]ackhandler.StreamFrame, protocol.ByteCount) {
			var length protocol.ByteCount
			for _, f := range frames {
				length += f.Frame.Length(v)
			}
			return append(fs, frames...), length
		})
	}

	expectAppendControlFrames := func(frames ...ackhandler.Frame) {
		framer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(fs []ackhandler.Frame, _ protocol.ByteCount, v protocol.VersionNumber) ([]ackhandler.Frame, protocol.ByteCount) {
			var length protocol.ByteCount
			for _, f := range frames {
				length += f.Frame.Length(v)
			}
			return append(fs, frames...), length
		})
	}

	BeforeEach(func() {
		rand.Seed(uint64(GinkgoRandomSeed()))
		retransmissionQueue = newRetransmissionQueue()
		mockSender := NewMockStreamSender(mockCtrl)
		mockSender.EXPECT().onHasStreamData(gomock.Any()).AnyTimes()
		initialStream = NewMockCryptoStream(mockCtrl)
		handshakeStream = NewMockCryptoStream(mockCtrl)
		framer = NewMockFrameSource(mockCtrl)
		ackFramer = NewMockAckFrameSource(mockCtrl)
		sealingManager = NewMockSealingManager(mockCtrl)
		pnManager = mockackhandler.NewMockSentPacketHandler(mockCtrl)
		datagramQueue = newDatagramQueue(func() {}, utils.DefaultLogger)

		packer = newPacketPacker(protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}), func() protocol.ConnectionID { return connID }, initialStream, handshakeStream, pnManager, retransmissionQueue, sealingManager, framer, ackFramer, datagramQueue, protocol.PerspectiveServer)
	})

	Context("determining the maximum packet size", func() {
		It("uses the minimum initial size, if it can't determine if the remote address is IPv4 or IPv6", func() {
			Expect(getMaxPacketSize(&net.TCPAddr{})).To(BeEquivalentTo(protocol.MinInitialPacketSize))
		})

		It("uses the maximum IPv4 packet size, if the remote address is IPv4", func() {
			addr := &net.UDPAddr{IP: net.IPv4(11, 12, 13, 14), Port: 1337}
			Expect(getMaxPacketSize(addr)).To(BeEquivalentTo(protocol.InitialPacketSizeIPv4))
		})

		It("uses the maximum IPv6 packet size, if the remote address is IPv6", func() {
			ip := net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
			addr := &net.UDPAddr{IP: ip, Port: 1337}
			Expect(getMaxPacketSize(addr)).To(BeEquivalentTo(protocol.InitialPacketSizeIPv6))
		})
	})

	Context("generating a packet header", func() {
		It("uses the Long Header format", func() {
			pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen3)
			h := packer.getLongHeader(protocol.EncryptionHandshake, protocol.Version1)
			Expect(h.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
			Expect(h.PacketNumberLen).To(Equal(protocol.PacketNumberLen3))
			Expect(h.Version).To(Equal(protocol.Version1))
		})

		It("sets source and destination connection ID", func() {
			pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			srcConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
			destConnID := protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1})
			packer.srcConnID = srcConnID
			packer.getDestConnID = func() protocol.ConnectionID { return destConnID }
			h := packer.getLongHeader(protocol.EncryptionHandshake, protocol.Version1)
			Expect(h.SrcConnectionID).To(Equal(srcConnID))
			Expect(h.DestConnectionID).To(Equal(destConnID))
		})
	})

	Context("encrypting packets", func() {
		It("encrypts a packet", func() {
			pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x1337), protocol.PacketNumberLen2)
			pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x1337))
			sealer := mocks.NewMockShortHeaderSealer(mockCtrl)
			sealer.EXPECT().Overhead().Return(4).AnyTimes()
			var hdrRaw []byte
			gomock.InOrder(
				sealer.EXPECT().KeyPhase().Return(protocol.KeyPhaseOne),
				sealer.EXPECT().Seal(gomock.Any(), gomock.Any(), protocol.PacketNumber(0x1337), gomock.Any()).DoAndReturn(func(_, src []byte, _ protocol.PacketNumber, aad []byte) []byte {
					hdrRaw = append([]byte{}, aad...)
					return append(src, []byte{0xde, 0xca, 0xfb, 0xad}...)
				}),
				sealer.EXPECT().EncryptHeader(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(sample []byte, firstByte *byte, pnBytes []byte) {
					Expect(firstByte).To(Equal(&hdrRaw[0]))
					Expect(pnBytes).To(Equal(hdrRaw[len(hdrRaw)-2:]))
					*firstByte ^= 0xff // invert the first byte
					// invert the packet number bytes
					for i := range pnBytes {
						pnBytes[i] ^= 0xff
					}
				}),
			)
			framer.EXPECT().HasData().Return(true)
			sealingManager.EXPECT().GetInitialSealer().Return(nil, nil)
			sealingManager.EXPECT().GetHandshakeSealer().Return(nil, nil)
			sealingManager.EXPECT().Get1RTTSealer().Return(sealer, nil)
			ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false)
			expectAppendControlFrames()
			f := &wire.StreamFrame{Data: []byte{0xde, 0xca, 0xfb, 0xad}}
			expectAppendStreamFrames(ackhandler.StreamFrame{Frame: f})
			p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			Expect(p.longHdrPackets).To(BeEmpty())
			Expect(p.shortHdrPacket).ToNot(BeNil())
			Expect(p.shortHdrPacket.Frames).To(BeEmpty())
			Expect(p.shortHdrPacket.StreamFrames).To(HaveLen(1))
			Expect(p.shortHdrPacket.StreamFrames[0].Frame).To(Equal(f))
			hdrRawEncrypted := append([]byte{}, hdrRaw...)
			hdrRawEncrypted[0] ^= 0xff
			hdrRawEncrypted[len(hdrRaw)-2] ^= 0xff
			hdrRawEncrypted[len(hdrRaw)-1] ^= 0xff
			Expect(p.buffer.Data[0:len(hdrRaw)]).To(Equal(hdrRawEncrypted))
			Expect(p.buffer.Data[p.buffer.Len()-4:]).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})
	})

	Context("packing packets", func() {
		// getSealer gets a sealer that's expected to seal exactly one packet
		getSealer := func() *mocks.MockShortHeaderSealer {
			sealer := mocks.NewMockShortHeaderSealer(mockCtrl)
			sealer.EXPECT().KeyPhase().Return(protocol.KeyPhaseOne).AnyTimes()
			sealer.EXPECT().Overhead().Return(7).AnyTimes()
			sealer.EXPECT().EncryptHeader(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			sealer.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(dst, src []byte, pn protocol.PacketNumber, associatedData []byte) []byte {
				return append(src, bytes.Repeat([]byte{'s'}, sealer.Overhead())...)
			}).AnyTimes()
			return sealer
		}

		Context("packing ACK packets", func() {
			It("doesn't pack a packet if there's no ACK to send", func() {
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, true)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, true)
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, true)
				p, err := packer.PackCoalescedPacket(true, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p).To(BeNil())
			})

			It("packs Initial ACK-only packets, and pads them (for the client)", func() {
				packer.perspective = protocol.PerspectiveClient
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, true).Return(ack)
				p, err := packer.PackCoalescedPacket(true, maxPacketSize, protocol.Version1)
				Expect(err).NotTo(HaveOccurred())
				Expect(p).ToNot(BeNil())
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.longHdrPackets[0].EncryptionLevel()).To(Equal(protocol.EncryptionInitial))
				Expect(p.longHdrPackets[0].ack).To(Equal(ack))
				Expect(p.longHdrPackets[0].frames).To(BeEmpty())
				Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
				parsePacket(p.buffer.Data)
			})

			It("packs Initial ACK-only packets, and doesn't pads them (for the server)", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, true).Return(ack)
				p, err := packer.PackCoalescedPacket(true, maxPacketSize, protocol.Version1)
				Expect(err).NotTo(HaveOccurred())
				Expect(p).ToNot(BeNil())
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.longHdrPackets[0].EncryptionLevel()).To(Equal(protocol.EncryptionInitial))
				Expect(p.longHdrPackets[0].ack).To(Equal(ack))
				Expect(p.longHdrPackets[0].frames).To(BeEmpty())
				Expect(p.buffer.Len()).To(BeNumerically("<", 100))
				parsePacket(p.buffer.Data)
			})

			It("packs 1-RTT ACK-only packets, before handshake confirmation", func() {
				sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, true)
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, true).Return(ack)
				p, err := packer.PackCoalescedPacket(true, maxPacketSize, protocol.Version1)
				Expect(err).NotTo(HaveOccurred())
				Expect(p).ToNot(BeNil())
				Expect(p.longHdrPackets).To(BeEmpty())
				Expect(p.shortHdrPacket).ToNot(BeNil())
				Expect(p.shortHdrPacket.Ack).To(Equal(ack))
				Expect(p.shortHdrPacket.Frames).To(BeEmpty())
				parsePacket(p.buffer.Data)
			})

			It("packs 1-RTT ACK-only packets, after handshake confirmation", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, true).Return(ack)
				p, buffer, err := packer.PackAckOnlyPacket(maxPacketSize, protocol.Version1)
				Expect(err).NotTo(HaveOccurred())
				Expect(p).ToNot(BeNil())
				Expect(p.Ack).To(Equal(ack))
				Expect(p.Frames).To(BeEmpty())
				parsePacket(buffer.Data)
			})
		})

		Context("packing 0-RTT packets", func() {
			BeforeEach(func() {
				packer.perspective = protocol.PerspectiveClient
				sealingManager.EXPECT().GetInitialSealer().Return(nil, nil).AnyTimes()
				sealingManager.EXPECT().GetHandshakeSealer().Return(nil, nil).AnyTimes()
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
				initialStream.EXPECT().HasData().AnyTimes()
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, true).AnyTimes()
				handshakeStream.EXPECT().HasData().AnyTimes()
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, true).AnyTimes()
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, true).AnyTimes()
			})

			It("packs a 0-RTT packet", func() {
				sealingManager.EXPECT().Get0RTTSealer().Return(getSealer(), nil).AnyTimes()
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption0RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption0RTT).Return(protocol.PacketNumber(0x42))
				cf := ackhandler.Frame{Frame: &wire.MaxDataFrame{MaximumData: 0x1337}}
				framer.EXPECT().HasData().Return(true)
				framer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any(), protocol.Version1).DoAndReturn(func(frames []ackhandler.Frame, _ protocol.ByteCount, v protocol.VersionNumber) ([]ackhandler.Frame, protocol.ByteCount) {
					Expect(frames).To(BeEmpty())
					return append(frames, cf), cf.Frame.Length(v)
				})
				// TODO: check sizes
				framer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any(), protocol.Version1).DoAndReturn(func(frames []ackhandler.StreamFrame, _ protocol.ByteCount, _ protocol.VersionNumber) ([]ackhandler.StreamFrame, protocol.ByteCount) {
					return frames, 0
				})
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(p).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.longHdrPackets[0].header.Type).To(Equal(protocol.PacketType0RTT))
				Expect(p.longHdrPackets[0].EncryptionLevel()).To(Equal(protocol.Encryption0RTT))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame).To(Equal(cf.Frame))
				Expect(p.longHdrPackets[0].frames[0].Handler).ToNot(BeNil())
			})

			It("doesn't add an ACK-only 0-RTT packet", func() { // ACK frames cannot be sent in 0-RTT packets
				p, err := packer.PackCoalescedPacket(true, protocol.MaxByteCount, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p).To(BeNil())
			})
		})

		Context("packing CONNECTION_CLOSE", func() {
			It("clears the reason phrase for crypto errors", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				quicErr := qerr.NewLocalCryptoError(0x42, errors.New("crypto error"))
				quicErr.FrameType = 0x1234
				p, err := packer.PackConnectionClose(quicErr, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.longHdrPackets[0].header.Type).To(Equal(protocol.PacketTypeHandshake))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
				ccf := p.longHdrPackets[0].frames[0].Frame.(*wire.ConnectionCloseFrame)
				Expect(ccf.IsApplicationError).To(BeFalse())
				Expect(ccf.ErrorCode).To(BeEquivalentTo(0x100 + 0x42))
				Expect(ccf.FrameType).To(BeEquivalentTo(0x1234))
				Expect(ccf.ReasonPhrase).To(BeEmpty())
			})

			It("packs a CONNECTION_CLOSE in 1-RTT", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
				sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysDropped)
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				// expect no framer.PopStreamFrames
				p, err := packer.PackConnectionClose(&qerr.TransportError{
					ErrorCode:    qerr.CryptoBufferExceeded,
					ErrorMessage: "test error",
				}, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.longHdrPackets).To(BeEmpty())
				Expect(p.shortHdrPacket.Frames).To(HaveLen(1))
				Expect(p.shortHdrPacket.Frames[0].Frame).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
				ccf := p.shortHdrPacket.Frames[0].Frame.(*wire.ConnectionCloseFrame)
				Expect(ccf.IsApplicationError).To(BeFalse())
				Expect(ccf.ErrorCode).To(BeEquivalentTo(qerr.CryptoBufferExceeded))
				Expect(ccf.ReasonPhrase).To(Equal("test error"))
			})

			It("packs a CONNECTION_CLOSE in all available encryption levels, and replaces application errors in Initial and Handshake", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(1), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(1))
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(2), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(2))
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(3), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(3))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				p, err := packer.PackApplicationClose(&qerr.ApplicationError{
					ErrorCode:    0x1337,
					ErrorMessage: "test error",
				}, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.longHdrPackets).To(HaveLen(2))
				Expect(p.longHdrPackets[0].header.Type).To(Equal(protocol.PacketTypeInitial))
				Expect(p.longHdrPackets[0].header.PacketNumber).To(Equal(protocol.PacketNumber(1)))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
				ccf := p.longHdrPackets[0].frames[0].Frame.(*wire.ConnectionCloseFrame)
				Expect(ccf.IsApplicationError).To(BeFalse())
				Expect(ccf.ErrorCode).To(BeEquivalentTo(qerr.ApplicationErrorErrorCode))
				Expect(ccf.ReasonPhrase).To(BeEmpty())
				Expect(p.longHdrPackets[1].header.Type).To(Equal(protocol.PacketTypeHandshake))
				Expect(p.longHdrPackets[1].header.PacketNumber).To(Equal(protocol.PacketNumber(2)))
				Expect(p.longHdrPackets[1].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[1].frames[0].Frame).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
				ccf = p.longHdrPackets[1].frames[0].Frame.(*wire.ConnectionCloseFrame)
				Expect(ccf.IsApplicationError).To(BeFalse())
				Expect(ccf.ErrorCode).To(BeEquivalentTo(qerr.ApplicationErrorErrorCode))
				Expect(ccf.ReasonPhrase).To(BeEmpty())
				Expect(p.shortHdrPacket).ToNot(BeNil())
				Expect(p.shortHdrPacket.PacketNumber).To(Equal(protocol.PacketNumber(3)))
				Expect(p.shortHdrPacket.Frames).To(HaveLen(1))
				Expect(p.shortHdrPacket.Frames[0].Frame).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
				ccf = p.shortHdrPacket.Frames[0].Frame.(*wire.ConnectionCloseFrame)
				Expect(ccf.IsApplicationError).To(BeTrue())
				Expect(ccf.ErrorCode).To(BeEquivalentTo(0x1337))
				Expect(ccf.ReasonPhrase).To(Equal("test error"))
			})

			It("packs a CONNECTION_CLOSE in all available encryption levels, as a client", func() {
				packer.perspective = protocol.PerspectiveClient
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(1), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(1))
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(2), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(2))
				sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysDropped)
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				p, err := packer.PackApplicationClose(&qerr.ApplicationError{
					ErrorCode:    0x1337,
					ErrorMessage: "test error",
				}, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.buffer.Len()).To(BeNumerically("<", protocol.MinInitialPacketSize))
				Expect(p.longHdrPackets[0].header.Type).To(Equal(protocol.PacketTypeHandshake))
				Expect(p.longHdrPackets[0].header.PacketNumber).To(Equal(protocol.PacketNumber(1)))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
				ccf := p.longHdrPackets[0].frames[0].Frame.(*wire.ConnectionCloseFrame)
				Expect(ccf.IsApplicationError).To(BeFalse())
				Expect(ccf.ErrorCode).To(BeEquivalentTo(qerr.ApplicationErrorErrorCode))
				Expect(ccf.ReasonPhrase).To(BeEmpty())
				Expect(p.shortHdrPacket).ToNot(BeNil())
				Expect(p.shortHdrPacket.PacketNumber).To(Equal(protocol.PacketNumber(2)))
				Expect(p.shortHdrPacket.Frames).To(HaveLen(1))
				Expect(p.shortHdrPacket.Frames[0].Frame).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
				ccf = p.shortHdrPacket.Frames[0].Frame.(*wire.ConnectionCloseFrame)
				Expect(ccf.IsApplicationError).To(BeTrue())
				Expect(ccf.ErrorCode).To(BeEquivalentTo(0x1337))
				Expect(ccf.ReasonPhrase).To(Equal("test error"))
			})

			It("packs a CONNECTION_CLOSE in all available encryption levels and pads, as a client", func() {
				packer.perspective = protocol.PerspectiveClient
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(1), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(1))
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption0RTT).Return(protocol.PacketNumber(2), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption0RTT).Return(protocol.PacketNumber(2))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				sealingManager.EXPECT().Get0RTTSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				p, err := packer.PackApplicationClose(&qerr.ApplicationError{
					ErrorCode:    0x1337,
					ErrorMessage: "test error",
				}, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.longHdrPackets).To(HaveLen(2))
				Expect(p.buffer.Len()).To(BeNumerically(">=", protocol.MinInitialPacketSize))
				Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
				Expect(p.longHdrPackets[0].header.Type).To(Equal(protocol.PacketTypeInitial))
				Expect(p.longHdrPackets[0].header.PacketNumber).To(Equal(protocol.PacketNumber(1)))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
				ccf := p.longHdrPackets[0].frames[0].Frame.(*wire.ConnectionCloseFrame)
				Expect(ccf.IsApplicationError).To(BeFalse())
				Expect(ccf.ErrorCode).To(BeEquivalentTo(qerr.ApplicationErrorErrorCode))
				Expect(ccf.ReasonPhrase).To(BeEmpty())
				Expect(p.longHdrPackets[1].header.Type).To(Equal(protocol.PacketType0RTT))
				Expect(p.longHdrPackets[1].header.PacketNumber).To(Equal(protocol.PacketNumber(2)))
				Expect(p.longHdrPackets[1].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[1].frames[0].Frame).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
				ccf = p.longHdrPackets[1].frames[0].Frame.(*wire.ConnectionCloseFrame)
				Expect(ccf.IsApplicationError).To(BeTrue())
				Expect(ccf.ErrorCode).To(BeEquivalentTo(0x1337))
				Expect(ccf.ReasonPhrase).To(Equal("test error"))
				hdrs, more := parsePacket(p.buffer.Data)
				Expect(hdrs).To(HaveLen(2))
				Expect(hdrs[0].Type).To(Equal(protocol.PacketTypeInitial))
				Expect(hdrs[1].Type).To(Equal(protocol.PacketType0RTT))
				Expect(more).To(BeEmpty())
			})
		})

		Context("packing normal packets", func() {
			It("returns nil when no packet is queued", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				// don't expect any calls to PopPacketNumber
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, true)
				framer.EXPECT().HasData()
				_, err := packer.AppendPacket(getPacketBuffer(), maxPacketSize, protocol.Version1)
				Expect(err).To(MatchError(errNothingToPack))
			})

			It("appends single packets", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				framer.EXPECT().HasData().Return(true)
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false)
				expectAppendControlFrames()
				f := &wire.StreamFrame{
					StreamID: 5,
					Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				}
				expectAppendStreamFrames(ackhandler.StreamFrame{Frame: f})
				buffer := getPacketBuffer()
				buffer.Data = append(buffer.Data, []byte("foobar")...)
				p, err := packer.AppendPacket(buffer, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p).ToNot(BeNil())
				b, err := f.Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.Frames).To(BeEmpty())
				Expect(p.StreamFrames).To(HaveLen(1))
				Expect(p.StreamFrames[0].Frame.StreamID).To(Equal(f.StreamID))
				Expect(buffer.Data[:6]).To(Equal([]byte("foobar"))) // make sure the packet was actually appended
				Expect(buffer.Data).To(ContainSubstring(string(b)))
			})

			It("packs a single ACK", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 42, Smallest: 1}}}
				framer.EXPECT().HasData()
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, true).Return(ack)
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				p, err := packer.AppendPacket(getPacketBuffer(), maxPacketSize, protocol.Version1)
				Expect(err).NotTo(HaveOccurred())
				Expect(p).ToNot(BeNil())
				Expect(p.Ack).To(Equal(ack))
			})

			It("packs control frames", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				framer.EXPECT().HasData().Return(true)
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false)
				frames := []ackhandler.Frame{
					{Frame: &wire.ResetStreamFrame{}},
					{Frame: &wire.MaxDataFrame{}},
				}
				expectAppendControlFrames(frames...)
				expectAppendStreamFrames()
				buffer := getPacketBuffer()
				p, err := packer.AppendPacket(buffer, maxPacketSize, protocol.Version1)
				Expect(p).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(p.Frames).To(HaveLen(2))
				for i, f := range p.Frames {
					Expect(f).To(BeAssignableToTypeOf(frames[i]))
				}
				Expect(buffer.Len()).ToNot(BeZero())
			})

			It("packs DATAGRAM frames", func() {
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, true)
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				f := &wire.DatagramFrame{
					DataLenPresent: true,
					Data:           []byte("foobar"),
				}
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					datagramQueue.AddAndWait(f)
				}()
				// make sure the DATAGRAM has actually been queued
				time.Sleep(scaleDuration(20 * time.Millisecond))

				framer.EXPECT().HasData()
				buffer := getPacketBuffer()
				p, err := packer.AppendPacket(buffer, maxPacketSize, protocol.Version1)
				Expect(p).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(p.Frames).To(HaveLen(1))
				Expect(p.Frames[0].Frame).To(Equal(f))
				Expect(buffer.Data).ToNot(BeEmpty())
				Eventually(done).Should(BeClosed())
			})

			It("doesn't pack a DATAGRAM frame if the ACK frame is too large", func() {
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, true).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 100}}})
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				f := &wire.DatagramFrame{
					DataLenPresent: true,
					Data:           make([]byte, maxPacketSize-10),
				}
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					datagramQueue.AddAndWait(f)
				}()
				// make sure the DATAGRAM has actually been queued
				time.Sleep(scaleDuration(20 * time.Millisecond))

				framer.EXPECT().HasData()
				buffer := getPacketBuffer()
				p, err := packer.AppendPacket(buffer, maxPacketSize, protocol.Version1)
				Expect(p).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(p.Ack).ToNot(BeNil())
				Expect(p.Frames).To(BeEmpty())
				Expect(buffer.Data).ToNot(BeEmpty())
				datagramQueue.CloseWithError(nil)
				Eventually(done).Should(BeClosed())
			})

			It("accounts for the space consumed by control frames", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				framer.EXPECT().HasData().Return(true)
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false)
				var maxSize protocol.ByteCount
				gomock.InOrder(
					framer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any(), protocol.Version1).DoAndReturn(func(fs []ackhandler.Frame, maxLen protocol.ByteCount, _ protocol.VersionNumber) ([]ackhandler.Frame, protocol.ByteCount) {
						maxSize = maxLen
						return fs, 444
					}),
					framer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any(), protocol.Version1).Do(func(fs []ackhandler.StreamFrame, maxLen protocol.ByteCount, _ protocol.VersionNumber) ([]ackhandler.StreamFrame, protocol.ByteCount) {
						Expect(maxLen).To(Equal(maxSize - 444))
						return fs, 0
					}),
				)
				_, err := packer.AppendPacket(getPacketBuffer(), maxPacketSize, protocol.Version1)
				Expect(err).To(MatchError(errNothingToPack))
			})

			It("pads if payload length + packet number length is smaller than 4, for Long Header packets", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen1)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
				sealer := getSealer()
				sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
				sealingManager.EXPECT().GetHandshakeSealer().Return(sealer, nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				packer.retransmissionQueue.addHandshake(&wire.PingFrame{})
				handshakeStream.EXPECT().HasData()
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, false)
				packet, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(packet).ToNot(BeNil())
				Expect(packet.longHdrPackets).To(HaveLen(1))
				// cut off the tag that the mock sealer added
				// packet.buffer.Data = packet.buffer.Data[:packet.buffer.Len()-protocol.ByteCount(sealer.Overhead())]
				hdr, _, _, err := wire.ParsePacket(packet.buffer.Data)
				Expect(err).ToNot(HaveOccurred())
				data := packet.buffer.Data
				r := bytes.NewReader(data)
				extHdr, err := hdr.ParseExtended(r, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(extHdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen1))
				Expect(r.Len()).To(Equal(4 - 1 /* packet number length */ + sealer.Overhead()))
				// the first bytes of the payload should be a 2 PADDING frames...
				firstPayloadByte, err := r.ReadByte()
				Expect(err).ToNot(HaveOccurred())
				Expect(firstPayloadByte).To(Equal(byte(0)))
				secondPayloadByte, err := r.ReadByte()
				Expect(err).ToNot(HaveOccurred())
				Expect(secondPayloadByte).To(Equal(byte(0)))
				// ... followed by the PING
				frameParser := wire.NewFrameParser(false)
				l, frame, err := frameParser.ParseNext(data[len(data)-r.Len():], protocol.Encryption1RTT, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(BeAssignableToTypeOf(&wire.PingFrame{}))
				Expect(r.Len() - l).To(Equal(sealer.Overhead()))
			})

			It("pads if payload length + packet number length is smaller than 4", func() {
				f := &wire.StreamFrame{
					StreamID: 0x10, // small stream ID, such that only a single byte is consumed
					Fin:      true,
				}
				Expect(f.Length(protocol.Version1)).To(BeEquivalentTo(2))
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen1)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				sealer := getSealer()
				sealingManager.EXPECT().Get1RTTSealer().Return(sealer, nil)
				framer.EXPECT().HasData().Return(true)
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false)
				expectAppendControlFrames()
				expectAppendStreamFrames(ackhandler.StreamFrame{Frame: f})
				buffer := getPacketBuffer()
				_, err := packer.AppendPacket(buffer, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				// cut off the tag that the mock sealer added
				buffer.Data = buffer.Data[:buffer.Len()-protocol.ByteCount(sealer.Overhead())]
				data := buffer.Data
				l, _, pnLen, _, err := wire.ParseShortHeader(data, connID.Len())
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(data[l:])
				Expect(pnLen).To(Equal(protocol.PacketNumberLen1))
				Expect(r.Len()).To(Equal(4 - 1 /* packet number length */))
				// the first byte of the payload should be a PADDING frame...
				firstPayloadByte, err := r.ReadByte()
				Expect(err).ToNot(HaveOccurred())
				Expect(firstPayloadByte).To(Equal(byte(0)))
				// ... followed by the STREAM frame
				frameParser := wire.NewFrameParser(true)
				l, frame, err := frameParser.ParseNext(buffer.Data[len(data)-r.Len():], protocol.Encryption1RTT, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(BeAssignableToTypeOf(&wire.StreamFrame{}))
				sf := frame.(*wire.StreamFrame)
				Expect(sf.StreamID).To(Equal(f.StreamID))
				Expect(sf.Fin).To(Equal(f.Fin))
				Expect(sf.Data).To(BeEmpty())
				Expect(r.Len() - l).To(BeZero())
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
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				framer.EXPECT().HasData().Return(true)
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false)
				expectAppendControlFrames()
				expectAppendStreamFrames(ackhandler.StreamFrame{Frame: f1}, ackhandler.StreamFrame{Frame: f2}, ackhandler.StreamFrame{Frame: f3})
				p, err := packer.AppendPacket(getPacketBuffer(), maxPacketSize, protocol.Version1)
				Expect(p).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(p.Frames).To(BeEmpty())
				Expect(p.StreamFrames).To(HaveLen(3))
				Expect(p.StreamFrames[0].Frame.Data).To(Equal([]byte("frame 1")))
				Expect(p.StreamFrames[1].Frame.Data).To(Equal([]byte("frame 2")))
				Expect(p.StreamFrames[2].Frame.Data).To(Equal([]byte("frame 3")))
			})

			Context("making ACK packets ack-eliciting", func() {
				sendMaxNumNonAckElicitingAcks := func() {
					for i := 0; i < protocol.MaxNonAckElicitingAcks; i++ {
						pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
						pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
						sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
						framer.EXPECT().HasData().Return(true)
						ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
						expectAppendControlFrames()
						expectAppendStreamFrames()
						p, err := packer.AppendPacket(getPacketBuffer(), maxPacketSize, protocol.Version1)
						Expect(p).ToNot(BeNil())
						Expect(err).ToNot(HaveOccurred())
						Expect(p.Ack).ToNot(BeNil())
						Expect(p.Frames).To(BeEmpty())
					}
				}

				It("adds a PING frame when it's supposed to send a ack-eliciting packet", func() {
					sendMaxNumNonAckElicitingAcks()
					pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
					pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
					sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
					framer.EXPECT().HasData().Return(true)
					ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
					expectAppendControlFrames()
					expectAppendStreamFrames()
					p, err := packer.AppendPacket(getPacketBuffer(), maxPacketSize, protocol.Version1)
					Expect(p).ToNot(BeNil())
					Expect(err).ToNot(HaveOccurred())
					var hasPing bool
					for _, f := range p.Frames {
						if _, ok := f.Frame.(*wire.PingFrame); ok {
							hasPing = true
							Expect(f.Handler).To(BeNil()) // make sure the PING is not retransmitted if lost
						}
					}
					Expect(hasPing).To(BeTrue())
					// make sure the next packet doesn't contain another PING
					pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
					pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
					sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
					framer.EXPECT().HasData().Return(true)
					ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
					expectAppendControlFrames()
					expectAppendStreamFrames()
					p, err = packer.AppendPacket(getPacketBuffer(), maxPacketSize, protocol.Version1)
					Expect(p).ToNot(BeNil())
					Expect(err).ToNot(HaveOccurred())
					Expect(p.Ack).ToNot(BeNil())
					Expect(p.Frames).To(BeEmpty())
				})

				It("waits until there's something to send before adding a PING frame", func() {
					sendMaxNumNonAckElicitingAcks()
					// nothing to send
					pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
					sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
					framer.EXPECT().HasData().Return(true)
					expectAppendControlFrames()
					expectAppendStreamFrames()
					ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false)
					_, err := packer.AppendPacket(getPacketBuffer(), maxPacketSize, protocol.Version1)
					Expect(err).To(MatchError(errNothingToPack))
					// now add some frame to send
					expectAppendControlFrames()
					expectAppendStreamFrames()
					pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
					pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
					sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
					framer.EXPECT().HasData().Return(true)
					ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
					ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false).Return(ack)
					p, err := packer.AppendPacket(getPacketBuffer(), maxPacketSize, protocol.Version1)
					Expect(err).ToNot(HaveOccurred())
					Expect(p.Ack).To(Equal(ack))
					var hasPing bool
					for _, f := range p.Frames {
						if _, ok := f.Frame.(*wire.PingFrame); ok {
							hasPing = true
							Expect(f.Handler).To(BeNil()) // make sure the PING is not retransmitted if lost
						}
					}
					Expect(hasPing).To(BeTrue())
				})

				It("doesn't send a PING if it already sent another ack-eliciting frame", func() {
					sendMaxNumNonAckElicitingAcks()
					pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
					pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
					sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
					framer.EXPECT().HasData().Return(true)
					ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false)
					expectAppendStreamFrames()
					expectAppendControlFrames(ackhandler.Frame{Frame: &wire.MaxDataFrame{}})
					p, err := packer.AppendPacket(getPacketBuffer(), maxPacketSize, protocol.Version1)
					Expect(err).ToNot(HaveOccurred())
					Expect(p).ToNot(BeNil())
					Expect(p.Frames).ToNot(ContainElement(&wire.PingFrame{}))
				})
			})
		})

		Context("packing crypto packets", func() {
			It("sets the length", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
				f := &wire.CryptoFrame{
					Offset: 0x1337,
					Data:   []byte("foobar"),
				}
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, false)
				handshakeStream.EXPECT().HasData().Return(true).AnyTimes()
				handshakeStream.EXPECT().PopCryptoFrame(gomock.Any()).Return(f)
				sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p).ToNot(BeNil())
				parsePacket(p.buffer.Data)
			})

			It("packs an Initial packet and pads it", func() {
				packer.perspective = protocol.PerspectiveClient
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen1)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, false)
				initialStream.EXPECT().HasData().Return(true).Times(2)
				initialStream.EXPECT().PopCryptoFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) *wire.CryptoFrame {
					return &wire.CryptoFrame{Offset: 0x42, Data: []byte("initial")}
				})
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.buffer.Len()).To(BeNumerically(">=", protocol.MinInitialPacketSize))
				Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.longHdrPackets[0].EncryptionLevel()).To(Equal(protocol.EncryptionInitial))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame.(*wire.CryptoFrame).Data).To(Equal([]byte("initial")))
				hdrs, more := parsePacket(p.buffer.Data)
				Expect(hdrs).To(HaveLen(1))
				Expect(hdrs[0].Type).To(Equal(protocol.PacketTypeInitial))
				Expect(more).To(BeEmpty())
			})

			It("packs a maximum size Handshake packet", func() {
				var f *wire.CryptoFrame
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, true)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, false)
				initialStream.EXPECT().HasData()
				handshakeStream.EXPECT().HasData().Return(true).Times(2)
				handshakeStream.EXPECT().PopCryptoFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) *wire.CryptoFrame {
					f = &wire.CryptoFrame{Offset: 0x1337}
					f.Data = bytes.Repeat([]byte{'f'}, int(size-f.Length(protocol.Version1)-1))
					Expect(f.Length(protocol.Version1)).To(Equal(size))
					return f
				})
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
				parsePacket(p.buffer.Data)
			})

			It("packs a coalesced packet with Initial / Handshake, and pads it", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24))
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, false)
				// don't EXPECT any calls for a Handshake ACK frame
				initialStream.EXPECT().HasData().Return(true).Times(2)
				initialStream.EXPECT().PopCryptoFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) *wire.CryptoFrame {
					return &wire.CryptoFrame{Offset: 0x42, Data: []byte("initial")}
				})
				handshakeStream.EXPECT().HasData().Return(true).Times(2)
				handshakeStream.EXPECT().PopCryptoFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) *wire.CryptoFrame {
					return &wire.CryptoFrame{Offset: 0x1337, Data: []byte("handshake")}
				})
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
				Expect(p.longHdrPackets).To(HaveLen(2))
				Expect(p.shortHdrPacket).To(BeNil())
				Expect(p.longHdrPackets[0].EncryptionLevel()).To(Equal(protocol.EncryptionInitial))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame.(*wire.CryptoFrame).Data).To(Equal([]byte("initial")))
				Expect(p.longHdrPackets[1].EncryptionLevel()).To(Equal(protocol.EncryptionHandshake))
				Expect(p.longHdrPackets[1].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[1].frames[0].Frame.(*wire.CryptoFrame).Data).To(Equal([]byte("handshake")))
				hdrs, more := parsePacket(p.buffer.Data)
				Expect(hdrs).To(HaveLen(2))
				Expect(hdrs[0].Type).To(Equal(protocol.PacketTypeInitial))
				Expect(hdrs[1].Type).To(Equal(protocol.PacketTypeHandshake))
				Expect(more).To(BeEmpty())
			})

			It("packs a coalesced packet with Initial / super short Handshake, and pads it", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24))
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen1)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, false)
				// don't EXPECT any calls for a Handshake ACK frame
				initialStream.EXPECT().HasData().Return(true).Times(2)
				initialStream.EXPECT().PopCryptoFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) *wire.CryptoFrame {
					return &wire.CryptoFrame{Offset: 0x42, Data: []byte("initial")}
				})
				handshakeStream.EXPECT().HasData()
				packer.retransmissionQueue.addHandshake(&wire.PingFrame{})
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
				Expect(p.longHdrPackets).To(HaveLen(2))
				Expect(p.shortHdrPacket).To(BeNil())
				Expect(p.longHdrPackets[0].EncryptionLevel()).To(Equal(protocol.EncryptionInitial))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame.(*wire.CryptoFrame).Data).To(Equal([]byte("initial")))
				Expect(p.longHdrPackets[1].EncryptionLevel()).To(Equal(protocol.EncryptionHandshake))
				Expect(p.longHdrPackets[1].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[1].frames[0].Frame).To(BeAssignableToTypeOf(&wire.PingFrame{}))
				hdrs, more := parsePacket(p.buffer.Data)
				Expect(hdrs).To(HaveLen(2))
				Expect(hdrs[0].Type).To(Equal(protocol.PacketTypeInitial))
				Expect(hdrs[1].Type).To(Equal(protocol.PacketTypeHandshake))
				Expect(more).To(BeEmpty())
			})

			It("packs a coalesced packet with super short Initial / super short Handshake, and pads it", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen1)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24))
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen1)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any())
				initialStream.EXPECT().HasData()
				handshakeStream.EXPECT().HasData()
				packer.retransmissionQueue.addInitial(&wire.PingFrame{})
				packer.retransmissionQueue.addHandshake(&wire.PingFrame{})
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
				Expect(p.longHdrPackets).To(HaveLen(2))
				Expect(p.longHdrPackets[0].EncryptionLevel()).To(Equal(protocol.EncryptionInitial))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame).To(BeAssignableToTypeOf(&wire.PingFrame{}))
				Expect(p.longHdrPackets[1].EncryptionLevel()).To(Equal(protocol.EncryptionHandshake))
				Expect(p.longHdrPackets[1].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[1].frames[0].Frame).To(BeAssignableToTypeOf(&wire.PingFrame{}))
				hdrs, more := parsePacket(p.buffer.Data)
				Expect(hdrs).To(HaveLen(2))
				Expect(hdrs[0].Type).To(Equal(protocol.PacketTypeInitial))
				Expect(hdrs[1].Type).To(Equal(protocol.PacketTypeHandshake))
				Expect(more).To(BeEmpty())
			})

			It("packs a coalesced packet with Initial / super short 1-RTT, and pads it", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24))
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen1)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, false)
				initialStream.EXPECT().HasData().Return(true).Times(2)
				initialStream.EXPECT().PopCryptoFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) *wire.CryptoFrame {
					return &wire.CryptoFrame{Offset: 0x42, Data: []byte("initial")}
				})
				expectAppendControlFrames()
				expectAppendStreamFrames()
				framer.EXPECT().HasData().Return(true)
				packer.retransmissionQueue.addAppData(&wire.PingFrame{})
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.longHdrPackets[0].EncryptionLevel()).To(Equal(protocol.EncryptionInitial))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame.(*wire.CryptoFrame).Data).To(Equal([]byte("initial")))
				Expect(p.shortHdrPacket).ToNot(BeNil())
				Expect(p.shortHdrPacket.Frames).To(HaveLen(1))
				Expect(p.shortHdrPacket.Frames[0].Frame).To(BeAssignableToTypeOf(&wire.PingFrame{}))
				hdrs, more := parsePacket(p.buffer.Data)
				Expect(hdrs).To(HaveLen(1))
				Expect(hdrs[0].Type).To(Equal(protocol.PacketTypeInitial))
				Expect(more).ToNot(BeEmpty())
				parseShortHeaderPacket(more)
			})

			It("packs a coalesced packet with Initial / 0-RTT, and pads it", func() {
				packer.perspective = protocol.PerspectiveClient
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24))
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption0RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption0RTT).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				sealingManager.EXPECT().Get0RTTSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				framer.EXPECT().HasData().Return(true)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, false)
				// don't EXPECT any calls for a Handshake ACK frame
				initialStream.EXPECT().HasData().Return(true).Times(2)
				initialStream.EXPECT().PopCryptoFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) *wire.CryptoFrame {
					return &wire.CryptoFrame{Offset: 0x42, Data: []byte("initial")}
				})
				expectAppendControlFrames()
				expectAppendStreamFrames(ackhandler.StreamFrame{Frame: &wire.StreamFrame{Data: []byte("foobar")}})
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.buffer.Len()).To(BeNumerically(">=", protocol.MinInitialPacketSize))
				Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
				Expect(p.longHdrPackets).To(HaveLen(2))
				Expect(p.longHdrPackets[0].EncryptionLevel()).To(Equal(protocol.EncryptionInitial))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame.(*wire.CryptoFrame).Data).To(Equal([]byte("initial")))
				Expect(p.longHdrPackets[0].streamFrames).To(BeEmpty())
				Expect(p.longHdrPackets[1].EncryptionLevel()).To(Equal(protocol.Encryption0RTT))
				Expect(p.longHdrPackets[1].frames).To(BeEmpty())
				Expect(p.longHdrPackets[1].streamFrames).To(HaveLen(1))
				Expect(p.longHdrPackets[1].streamFrames[0].Frame.Data).To(Equal([]byte("foobar")))
				hdrs, more := parsePacket(p.buffer.Data)
				Expect(hdrs).To(HaveLen(2))
				Expect(hdrs[0].Type).To(Equal(protocol.PacketTypeInitial))
				Expect(hdrs[1].Type).To(Equal(protocol.PacketType0RTT))
				Expect(more).To(BeEmpty())
			})

			It("packs a coalesced packet with Handshake / 1-RTT", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x24))
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				framer.EXPECT().HasData().Return(true)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, false)
				// don't EXPECT any calls for a 1-RTT ACK frame
				handshakeStream.EXPECT().HasData().Return(true).Times(2)
				handshakeStream.EXPECT().PopCryptoFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) *wire.CryptoFrame {
					return &wire.CryptoFrame{Offset: 0x1337, Data: []byte("handshake")}
				})
				expectAppendControlFrames()
				expectAppendStreamFrames(ackhandler.StreamFrame{Frame: &wire.StreamFrame{Data: []byte("foobar")}})
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.buffer.Len()).To(BeNumerically("<", 100))
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.longHdrPackets[0].EncryptionLevel()).To(Equal(protocol.EncryptionHandshake))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame.(*wire.CryptoFrame).Data).To(Equal([]byte("handshake")))
				Expect(p.shortHdrPacket).ToNot(BeNil())
				Expect(p.shortHdrPacket.Frames).To(BeEmpty())
				Expect(p.shortHdrPacket.StreamFrames).To(HaveLen(1))
				Expect(p.shortHdrPacket.StreamFrames[0].Frame.Data).To(Equal([]byte("foobar")))
				hdrs, more := parsePacket(p.buffer.Data)
				Expect(hdrs).To(HaveLen(1))
				Expect(hdrs[0].Type).To(Equal(protocol.PacketTypeHandshake))
				Expect(more).ToNot(BeEmpty())
				parseShortHeaderPacket(more)
			})

			It("doesn't add a coalesced packet if the remaining size is smaller than MaxCoalescedPacketSize", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x24))
				sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				// don't EXPECT any calls to GetHandshakeSealer and Get1RTTSealer
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, false)
				handshakeStream.EXPECT().HasData().Return(true).Times(2)
				handshakeStream.EXPECT().PopCryptoFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) *wire.CryptoFrame {
					s := size - protocol.MinCoalescedPacketSize
					f := &wire.CryptoFrame{Offset: 0x1337}
					f.Data = bytes.Repeat([]byte{'f'}, int(s-f.Length(protocol.Version1)-1))
					Expect(f.Length(protocol.Version1)).To(Equal(s))
					return f
				})
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.shortHdrPacket).To(BeNil())
				Expect(p.longHdrPackets[0].EncryptionLevel()).To(Equal(protocol.EncryptionHandshake))
				Expect(len(p.buffer.Data)).To(BeEquivalentTo(maxPacketSize - protocol.MinCoalescedPacketSize))
				parsePacket(p.buffer.Data)
			})

			It("pads if payload length + packet number length is smaller than 4, for Long Header packets", func() {
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen1)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
				sealer := getSealer()
				sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
				sealingManager.EXPECT().GetHandshakeSealer().Return(sealer, nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				packer.retransmissionQueue.addHandshake(&wire.PingFrame{})
				handshakeStream.EXPECT().HasData()
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, false)
				packet, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(packet).ToNot(BeNil())
				Expect(packet.longHdrPackets).To(HaveLen(1))
				Expect(packet.shortHdrPacket).To(BeNil())
				// cut off the tag that the mock sealer added
				// packet.buffer.Data = packet.buffer.Data[:packet.buffer.Len()-protocol.ByteCount(sealer.Overhead())]
				hdr, _, _, err := wire.ParsePacket(packet.buffer.Data)
				Expect(err).ToNot(HaveOccurred())
				data := packet.buffer.Data
				r := bytes.NewReader(data)
				extHdr, err := hdr.ParseExtended(r, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(extHdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen1))
				Expect(r.Len()).To(Equal(4 - 1 /* packet number length */ + sealer.Overhead()))
				// the first bytes of the payload should be a 2 PADDING frames...
				firstPayloadByte, err := r.ReadByte()
				Expect(err).ToNot(HaveOccurred())
				Expect(firstPayloadByte).To(Equal(byte(0)))
				secondPayloadByte, err := r.ReadByte()
				Expect(err).ToNot(HaveOccurred())
				Expect(secondPayloadByte).To(Equal(byte(0)))
				// ... followed by the PING
				frameParser := wire.NewFrameParser(false)
				l, frame, err := frameParser.ParseNext(data[len(data)-r.Len():], protocol.Encryption1RTT, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(BeAssignableToTypeOf(&wire.PingFrame{}))
				Expect(r.Len() - l).To(Equal(sealer.Overhead()))
			})

			It("adds retransmissions", func() {
				f := &wire.CryptoFrame{Data: []byte("Initial")}
				retransmissionQueue.addInitial(f)
				retransmissionQueue.addHandshake(&wire.CryptoFrame{Data: []byte("Handshake")})
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, false)
				initialStream.EXPECT().HasData()
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.longHdrPackets[0].EncryptionLevel()).To(Equal(protocol.EncryptionInitial))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.longHdrPackets[0].frames[0].Frame).To(Equal(f))
				Expect(p.longHdrPackets[0].frames[0].Handler).ToNot(BeNil())
			})

			It("sends an Initial packet containing only an ACK", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 10, Largest: 20}}}
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, true).Return(ack)
				initialStream.EXPECT().HasData().Times(2)
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42))
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.longHdrPackets[0].ack).To(Equal(ack))
			})

			It("doesn't pack anything if there's nothing to send at Initial and Handshake keys are not yet available", func() {
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				initialStream.EXPECT().HasData()
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, true)
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p).To(BeNil())
			})

			It("sends a Handshake packet containing only an ACK", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 10, Largest: 20}}}
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, true)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, true).Return(ack)
				initialStream.EXPECT().HasData()
				handshakeStream.EXPECT().HasData().Times(2)
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.longHdrPackets[0].ack).To(Equal(ack))
			})

			for _, pers := range []protocol.Perspective{protocol.PerspectiveServer, protocol.PerspectiveClient} {
				perspective := pers

				It(fmt.Sprintf("pads Initial packets to the required minimum packet size, for the %s", perspective), func() {
					token := []byte("initial token")
					packer.SetToken(token)
					f := &wire.CryptoFrame{Data: []byte("foobar")}
					pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
					pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42))
					sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
					sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
					sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
					sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
					ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, false)
					initialStream.EXPECT().HasData().Return(true).Times(2)
					initialStream.EXPECT().PopCryptoFrame(gomock.Any()).Return(f)
					packer.perspective = protocol.PerspectiveClient
					p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
					Expect(err).ToNot(HaveOccurred())
					Expect(p.buffer.Len()).To(BeNumerically(">=", protocol.MinInitialPacketSize))
					Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
					Expect(p.longHdrPackets).To(HaveLen(1))
					Expect(p.longHdrPackets[0].header.Token).To(Equal(token))
					Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
					cf := p.longHdrPackets[0].frames[0].Frame.(*wire.CryptoFrame)
					Expect(cf.Data).To(Equal([]byte("foobar")))
				})
			}

			It("adds an ACK frame", func() {
				f := &wire.CryptoFrame{Data: []byte("foobar")}
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 42, Largest: 1337}}}
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
				sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, false).Return(ack)
				initialStream.EXPECT().HasData().Return(true).Times(2)
				initialStream.EXPECT().PopCryptoFrame(gomock.Any()).Return(f)
				packer.perspective = protocol.PerspectiveClient
				p, err := packer.PackCoalescedPacket(false, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.longHdrPackets).To(HaveLen(1))
				Expect(p.longHdrPackets[0].ack).To(Equal(ack))
				Expect(p.longHdrPackets[0].frames).To(HaveLen(1))
				Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
			})
		})

		Context("packing probe packets", func() {
			for _, pers := range []protocol.Perspective{protocol.PerspectiveServer, protocol.PerspectiveClient} {
				perspective := pers

				It(fmt.Sprintf("packs an Initial probe packet and pads it, for the %s", perspective), func() {
					packer.perspective = perspective
					f := &wire.CryptoFrame{Data: []byte("Initial")}
					retransmissionQueue.addInitial(f)
					sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
					ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, false)
					initialStream.EXPECT().HasData()
					pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
					pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42))

					p, err := packer.MaybePackProbePacket(protocol.EncryptionInitial, maxPacketSize, protocol.Version1)
					Expect(err).ToNot(HaveOccurred())
					Expect(p).ToNot(BeNil())
					Expect(p.longHdrPackets).To(HaveLen(1))
					packet := p.longHdrPackets[0]
					Expect(packet.EncryptionLevel()).To(Equal(protocol.EncryptionInitial))
					Expect(p.buffer.Len()).To(BeNumerically(">=", protocol.MinInitialPacketSize))
					Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
					Expect(packet.frames).To(HaveLen(1))
					Expect(packet.frames[0].Frame).To(Equal(f))
					parsePacket(p.buffer.Data)
				})

				It(fmt.Sprintf("packs an Initial probe packet with 1 byte payload, for the %s", perspective), func() {
					packer.perspective = perspective
					retransmissionQueue.addInitial(&wire.PingFrame{})
					sealingManager.EXPECT().GetInitialSealer().Return(getSealer(), nil)
					ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, false)
					initialStream.EXPECT().HasData()
					pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen1)
					pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42))

					p, err := packer.MaybePackProbePacket(protocol.EncryptionInitial, maxPacketSize, protocol.Version1)
					Expect(err).ToNot(HaveOccurred())
					Expect(err).ToNot(HaveOccurred())
					Expect(p).ToNot(BeNil())
					Expect(p.longHdrPackets).To(HaveLen(1))
					packet := p.longHdrPackets[0]
					Expect(packet.EncryptionLevel()).To(Equal(protocol.EncryptionInitial))
					Expect(p.buffer.Len()).To(BeNumerically(">=", protocol.MinInitialPacketSize))
					Expect(p.buffer.Len()).To(BeEquivalentTo(maxPacketSize))
					Expect(packet.frames).To(HaveLen(1))
					Expect(packet.frames[0].Frame).To(BeAssignableToTypeOf(&wire.PingFrame{}))
					parsePacket(p.buffer.Data)
				})
			}

			It("packs a Handshake probe packet", func() {
				f := &wire.CryptoFrame{Data: []byte("Handshake")}
				retransmissionQueue.addHandshake(f)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, false)
				handshakeStream.EXPECT().HasData()
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))

				p, err := packer.MaybePackProbePacket(protocol.EncryptionHandshake, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(err).ToNot(HaveOccurred())
				Expect(p).ToNot(BeNil())
				Expect(p.longHdrPackets).To(HaveLen(1))
				packet := p.longHdrPackets[0]
				Expect(packet.EncryptionLevel()).To(Equal(protocol.EncryptionHandshake))
				Expect(packet.frames).To(HaveLen(1))
				Expect(packet.frames[0].Frame).To(Equal(f))
				parsePacket(p.buffer.Data)
			})

			It("packs a full size  Handshake probe packet", func() {
				f := &wire.CryptoFrame{Data: make([]byte, 2000)}
				retransmissionQueue.addHandshake(f)
				sealingManager.EXPECT().GetHandshakeSealer().Return(getSealer(), nil)
				ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, false)
				handshakeStream.EXPECT().HasData()
				pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))

				p, err := packer.MaybePackProbePacket(protocol.EncryptionHandshake, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(err).ToNot(HaveOccurred())
				Expect(p).ToNot(BeNil())
				Expect(p.longHdrPackets).To(HaveLen(1))
				packet := p.longHdrPackets[0]
				Expect(packet.EncryptionLevel()).To(Equal(protocol.EncryptionHandshake))
				Expect(packet.frames).To(HaveLen(1))
				Expect(packet.frames[0].Frame).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
				Expect(packet.length).To(Equal(maxPacketSize))
				parsePacket(p.buffer.Data)
			})

			It("packs a 1-RTT probe packet", func() {
				f := &wire.StreamFrame{Data: []byte("1-RTT")}
				retransmissionQueue.addInitial(f)
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false)
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				framer.EXPECT().HasData().Return(true)
				expectAppendControlFrames()
				expectAppendStreamFrames(ackhandler.StreamFrame{Frame: f})

				p, err := packer.MaybePackProbePacket(protocol.Encryption1RTT, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p).ToNot(BeNil())
				Expect(p.longHdrPackets).To(BeEmpty())
				Expect(p.shortHdrPacket).ToNot(BeNil())
				packet := p.shortHdrPacket
				Expect(packet.Frames).To(BeEmpty())
				Expect(packet.StreamFrames).To(HaveLen(1))
				Expect(packet.StreamFrames[0].Frame).To(Equal(f))
			})

			It("packs a full size 1-RTT probe packet", func() {
				f := &wire.StreamFrame{Data: make([]byte, 2000)}
				retransmissionQueue.addInitial(f)
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, false)
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
				framer.EXPECT().HasData().Return(true)
				expectAppendControlFrames()
				framer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any(), protocol.Version1).DoAndReturn(func(fs []ackhandler.StreamFrame, maxSize protocol.ByteCount, v protocol.VersionNumber) ([]ackhandler.StreamFrame, protocol.ByteCount) {
					sf, split := f.MaybeSplitOffFrame(maxSize, v)
					Expect(split).To(BeTrue())
					return append(fs, ackhandler.StreamFrame{Frame: sf}), sf.Length(v)
				})

				p, err := packer.MaybePackProbePacket(protocol.Encryption1RTT, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p).ToNot(BeNil())
				Expect(p.longHdrPackets).To(BeEmpty())
				Expect(p.shortHdrPacket).ToNot(BeNil())
				packet := p.shortHdrPacket
				Expect(packet.Frames).To(BeEmpty())
				Expect(packet.StreamFrames).To(HaveLen(1))
				Expect(packet.Length).To(Equal(maxPacketSize))
			})

			It("returns nil if there's no probe data to send", func() {
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, true)
				framer.EXPECT().HasData()

				packet, err := packer.MaybePackProbePacket(protocol.Encryption1RTT, maxPacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(packet).To(BeNil())
			})

			It("packs an MTU probe packet", func() {
				sealingManager.EXPECT().Get1RTTSealer().Return(getSealer(), nil)
				pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43))
				ping := ackhandler.Frame{Frame: &wire.PingFrame{}}
				const probePacketSize = maxPacketSize + 42
				p, buffer, err := packer.PackMTUProbePacket(ping, probePacketSize, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(p.Length).To(BeEquivalentTo(probePacketSize))
				Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(0x43)))
				Expect(buffer.Data).To(HaveLen(int(probePacketSize)))
				Expect(p.IsPathMTUProbePacket).To(BeTrue())
			})
		})
	})
})
