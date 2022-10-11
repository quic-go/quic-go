package quic

import (
	"bytes"
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/wire"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Unpacker", func() {
	const version = protocol.VersionTLS

	var (
		unpacker *packetUnpacker
		cs       *mocks.MockCryptoSetup
		connID   = protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
		payload  = []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
	)

	getHeader := func(extHdr *wire.ExtendedHeader) (*wire.Header, []byte) {
		buf := &bytes.Buffer{}
		ExpectWithOffset(1, extHdr.Write(buf, version)).To(Succeed())
		hdrLen := buf.Len()
		if extHdr.Length > protocol.ByteCount(extHdr.PacketNumberLen) {
			buf.Write(make([]byte, int(extHdr.Length)-int(extHdr.PacketNumberLen)))
		}
		hdr, _, _, err := wire.ParsePacket(buf.Bytes(), connID.Len())
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		return hdr, buf.Bytes()[:hdrLen]
	}

	BeforeEach(func() {
		cs = mocks.NewMockCryptoSetup(mockCtrl)
		unpacker = newPacketUnpacker(cs, 4, version).(*packetUnpacker)
	})

	It("errors when the packet is too small to obtain the header decryption sample, for long headers", func() {
		extHdr := &wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				DestConnectionID: connID,
				Version:          version,
			},
			PacketNumber:    1337,
			PacketNumberLen: protocol.PacketNumberLen2,
		}
		hdr, hdrRaw := getHeader(extHdr)
		data := append(hdrRaw, make([]byte, 2 /* fill up packet number */ +15 /* need 16 bytes */)...)
		opener := mocks.NewMockLongHeaderOpener(mockCtrl)
		cs.EXPECT().GetHandshakeOpener().Return(opener, nil)
		_, err := unpacker.UnpackLongHeader(hdr, time.Now(), data)
		Expect(err).To(BeAssignableToTypeOf(&headerParseError{}))
		var headerErr *headerParseError
		Expect(errors.As(err, &headerErr)).To(BeTrue())
		Expect(err).To(MatchError("Packet too small. Expected at least 20 bytes after the header, got 19"))
	})

	It("errors when the packet is too small to obtain the header decryption sample, for short headers", func() {
		_, hdrRaw := getHeader(&wire.ExtendedHeader{
			Header:          wire.Header{DestConnectionID: connID},
			PacketNumber:    1337,
			PacketNumberLen: protocol.PacketNumberLen2,
		})
		data := append(hdrRaw, make([]byte, 2 /* fill up packet number */ +15 /* need 16 bytes */)...)
		opener := mocks.NewMockShortHeaderOpener(mockCtrl)
		cs.EXPECT().Get1RTTOpener().Return(opener, nil)
		_, _, _, _, err := unpacker.UnpackShortHeader(time.Now(), data)
		Expect(err).To(BeAssignableToTypeOf(&headerParseError{}))
		Expect(err).To(MatchError("packet too small, expected at least 20 bytes after the header, got 19"))
	})

	It("opens Initial packets", func() {
		extHdr := &wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				Length:           3 + 6, // packet number len + payload
				DestConnectionID: connID,
				Version:          version,
			},
			PacketNumber:    2,
			PacketNumberLen: 3,
		}
		hdr, hdrRaw := getHeader(extHdr)
		opener := mocks.NewMockLongHeaderOpener(mockCtrl)
		gomock.InOrder(
			cs.EXPECT().GetInitialOpener().Return(opener, nil),
			opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any()),
			opener.EXPECT().DecodePacketNumber(protocol.PacketNumber(2), protocol.PacketNumberLen3).Return(protocol.PacketNumber(1234)),
			opener.EXPECT().Open(gomock.Any(), payload, protocol.PacketNumber(1234), hdrRaw).Return([]byte("decrypted"), nil),
		)
		packet, err := unpacker.UnpackLongHeader(hdr, time.Now(), append(hdrRaw, payload...))
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionInitial))
		Expect(packet.data).To(Equal([]byte("decrypted")))
	})

	It("opens 0-RTT packets", func() {
		extHdr := &wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketType0RTT,
				Length:           3 + 6, // packet number len + payload
				DestConnectionID: connID,
				Version:          version,
			},
			PacketNumber:    20,
			PacketNumberLen: 2,
		}
		hdr, hdrRaw := getHeader(extHdr)
		opener := mocks.NewMockLongHeaderOpener(mockCtrl)
		gomock.InOrder(
			cs.EXPECT().Get0RTTOpener().Return(opener, nil),
			opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any()),
			opener.EXPECT().DecodePacketNumber(protocol.PacketNumber(20), protocol.PacketNumberLen2).Return(protocol.PacketNumber(321)),
			opener.EXPECT().Open(gomock.Any(), payload, protocol.PacketNumber(321), hdrRaw).Return([]byte("decrypted"), nil),
		)
		packet, err := unpacker.UnpackLongHeader(hdr, time.Now(), append(hdrRaw, payload...))
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.Encryption0RTT))
		Expect(packet.data).To(Equal([]byte("decrypted")))
	})

	It("opens short header packets", func() {
		extHdr := &wire.ExtendedHeader{
			Header:          wire.Header{DestConnectionID: connID},
			KeyPhase:        protocol.KeyPhaseOne,
			PacketNumber:    99,
			PacketNumberLen: protocol.PacketNumberLen4,
		}
		_, hdrRaw := getHeader(extHdr)
		opener := mocks.NewMockShortHeaderOpener(mockCtrl)
		now := time.Now()
		gomock.InOrder(
			cs.EXPECT().Get1RTTOpener().Return(opener, nil),
			opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any()),
			opener.EXPECT().DecodePacketNumber(protocol.PacketNumber(99), protocol.PacketNumberLen4).Return(protocol.PacketNumber(321)),
			opener.EXPECT().Open(gomock.Any(), payload, now, protocol.PacketNumber(321), protocol.KeyPhaseOne, hdrRaw).Return([]byte("decrypted"), nil),
		)
		pn, pnLen, kp, data, err := unpacker.UnpackShortHeader(now, append(hdrRaw, payload...))
		Expect(err).ToNot(HaveOccurred())
		Expect(pn).To(Equal(protocol.PacketNumber(321)))
		Expect(pnLen).To(Equal(protocol.PacketNumberLen4))
		Expect(kp).To(Equal(protocol.KeyPhaseOne))
		Expect(data).To(Equal([]byte("decrypted")))
	})

	It("returns the error when getting the opener fails", func() {
		extHdr := &wire.ExtendedHeader{
			Header:          wire.Header{DestConnectionID: connID},
			PacketNumber:    0x1337,
			PacketNumberLen: 2,
		}
		_, hdrRaw := getHeader(extHdr)
		cs.EXPECT().Get1RTTOpener().Return(nil, handshake.ErrKeysNotYetAvailable)
		_, _, _, _, err := unpacker.UnpackShortHeader(time.Now(), append(hdrRaw, payload...))
		Expect(err).To(MatchError(handshake.ErrKeysNotYetAvailable))
	})

	It("errors on empty packets, for long header packets", func() {
		extHdr := &wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				DestConnectionID: connID,
				Version:          Version1,
			},
			KeyPhase:        protocol.KeyPhaseOne,
			PacketNumberLen: protocol.PacketNumberLen4,
		}
		hdr, hdrRaw := getHeader(extHdr)
		opener := mocks.NewMockLongHeaderOpener(mockCtrl)
		gomock.InOrder(
			cs.EXPECT().GetHandshakeOpener().Return(opener, nil),
			opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any()),
			opener.EXPECT().DecodePacketNumber(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(321)),
			opener.EXPECT().Open(gomock.Any(), payload, protocol.PacketNumber(321), hdrRaw).Return([]byte(""), nil),
		)
		_, err := unpacker.UnpackLongHeader(hdr, time.Now(), append(hdrRaw, payload...))
		Expect(err).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "empty packet",
		}))
	})

	It("errors on empty packets, for short header packets", func() {
		extHdr := &wire.ExtendedHeader{
			Header:          wire.Header{DestConnectionID: connID},
			KeyPhase:        protocol.KeyPhaseOne,
			PacketNumberLen: protocol.PacketNumberLen4,
		}
		_, hdrRaw := getHeader(extHdr)
		opener := mocks.NewMockShortHeaderOpener(mockCtrl)
		now := time.Now()
		gomock.InOrder(
			cs.EXPECT().Get1RTTOpener().Return(opener, nil),
			opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any()),
			opener.EXPECT().DecodePacketNumber(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(321)),
			opener.EXPECT().Open(gomock.Any(), payload, now, protocol.PacketNumber(321), protocol.KeyPhaseOne, hdrRaw).Return([]byte(""), nil),
		)
		_, _, _, _, err := unpacker.UnpackShortHeader(now, append(hdrRaw, payload...))
		Expect(err).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "empty packet",
		}))
	})

	It("returns the error when unpacking fails", func() {
		extHdr := &wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				Length:           3, // packet number len
				DestConnectionID: connID,
				Version:          version,
			},
			PacketNumber:    2,
			PacketNumberLen: 3,
		}
		hdr, hdrRaw := getHeader(extHdr)
		opener := mocks.NewMockLongHeaderOpener(mockCtrl)
		cs.EXPECT().GetHandshakeOpener().Return(opener, nil)
		opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any())
		opener.EXPECT().DecodePacketNumber(gomock.Any(), gomock.Any())
		unpackErr := &qerr.TransportError{ErrorCode: qerr.CryptoBufferExceeded}
		opener.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, unpackErr)
		_, err := unpacker.UnpackLongHeader(hdr, time.Now(), append(hdrRaw, payload...))
		Expect(err).To(MatchError(unpackErr))
	})

	It("defends against the timing side-channel when the reserved bits are wrong, for long header packets", func() {
		extHdr := &wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				DestConnectionID: connID,
				Version:          version,
			},
			PacketNumber:    0x1337,
			PacketNumberLen: 2,
		}
		hdr, hdrRaw := getHeader(extHdr)
		hdrRaw[0] |= 0xc
		opener := mocks.NewMockLongHeaderOpener(mockCtrl)
		opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any())
		cs.EXPECT().GetHandshakeOpener().Return(opener, nil)
		opener.EXPECT().DecodePacketNumber(gomock.Any(), gomock.Any())
		opener.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("payload"), nil)
		_, err := unpacker.UnpackLongHeader(hdr, time.Now(), append(hdrRaw, payload...))
		Expect(err).To(MatchError(wire.ErrInvalidReservedBits))
	})

	It("defends against the timing side-channel when the reserved bits are wrong, for short header packets", func() {
		extHdr := &wire.ExtendedHeader{
			Header:          wire.Header{DestConnectionID: connID},
			PacketNumber:    0x1337,
			PacketNumberLen: 2,
		}
		_, hdrRaw := getHeader(extHdr)
		hdrRaw[0] |= 0x18
		opener := mocks.NewMockShortHeaderOpener(mockCtrl)
		opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any())
		cs.EXPECT().Get1RTTOpener().Return(opener, nil)
		opener.EXPECT().DecodePacketNumber(gomock.Any(), gomock.Any())
		opener.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("payload"), nil)
		_, _, _, _, err := unpacker.UnpackShortHeader(time.Now(), append(hdrRaw, payload...))
		Expect(err).To(MatchError(wire.ErrInvalidReservedBits))
	})

	It("returns the decryption error, when unpacking a packet with wrong reserved bits fails, for long headers", func() {
		extHdr := &wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				DestConnectionID: connID,
				Version:          version,
			},
			PacketNumber:    0x1337,
			PacketNumberLen: 2,
		}
		hdr, hdrRaw := getHeader(extHdr)
		hdrRaw[0] |= 0x18
		opener := mocks.NewMockLongHeaderOpener(mockCtrl)
		opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any())
		cs.EXPECT().GetHandshakeOpener().Return(opener, nil)
		opener.EXPECT().DecodePacketNumber(gomock.Any(), gomock.Any())
		opener.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, handshake.ErrDecryptionFailed)
		_, err := unpacker.UnpackLongHeader(hdr, time.Now(), append(hdrRaw, payload...))
		Expect(err).To(MatchError(handshake.ErrDecryptionFailed))
	})

	It("returns the decryption error, when unpacking a packet with wrong reserved bits fails, for short headers", func() {
		extHdr := &wire.ExtendedHeader{
			Header:          wire.Header{DestConnectionID: connID},
			PacketNumber:    0x1337,
			PacketNumberLen: 2,
		}
		_, hdrRaw := getHeader(extHdr)
		hdrRaw[0] |= 0x18
		opener := mocks.NewMockShortHeaderOpener(mockCtrl)
		opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any())
		cs.EXPECT().Get1RTTOpener().Return(opener, nil)
		opener.EXPECT().DecodePacketNumber(gomock.Any(), gomock.Any())
		opener.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, handshake.ErrDecryptionFailed)
		_, _, _, _, err := unpacker.UnpackShortHeader(time.Now(), append(hdrRaw, payload...))
		Expect(err).To(MatchError(handshake.ErrDecryptionFailed))
	})

	It("decrypts the header", func() {
		extHdr := &wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				Length:           3, // packet number len
				DestConnectionID: connID,
				Version:          version,
			},
			PacketNumber:    0x1337,
			PacketNumberLen: 2,
		}
		hdr, hdrRaw := getHeader(extHdr)
		origHdrRaw := append([]byte{}, hdrRaw...) // save a copy of the header
		firstHdrByte := hdrRaw[0]
		hdrRaw[0] ^= 0xff             // invert the first byte
		hdrRaw[len(hdrRaw)-2] ^= 0xff // invert the packet number
		hdrRaw[len(hdrRaw)-1] ^= 0xff // invert the packet number
		Expect(hdrRaw[0]).ToNot(Equal(firstHdrByte))
		opener := mocks.NewMockLongHeaderOpener(mockCtrl)
		cs.EXPECT().GetHandshakeOpener().Return(opener, nil)
		gomock.InOrder(
			// we're using a 2 byte packet number, so the sample starts at the 3rd payload byte
			opener.EXPECT().DecryptHeader(
				[]byte{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18},
				&hdrRaw[0],
				append(hdrRaw[len(hdrRaw)-2:], []byte{1, 2}...)).Do(func(_ []byte, firstByte *byte, pnBytes []byte) {
				*firstByte ^= 0xff // invert the first byte back
				for i := range pnBytes {
					pnBytes[i] ^= 0xff // invert the packet number bytes
				}
			}),
			opener.EXPECT().DecodePacketNumber(protocol.PacketNumber(0x1337), protocol.PacketNumberLen2).Return(protocol.PacketNumber(0x7331)),
			opener.EXPECT().Open(gomock.Any(), gomock.Any(), protocol.PacketNumber(0x7331), origHdrRaw).Return([]byte{0}, nil),
		)
		data := hdrRaw
		for i := 1; i <= 100; i++ {
			data = append(data, uint8(i))
		}
		packet, err := unpacker.UnpackLongHeader(hdr, time.Now(), data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x7331)))
	})
})
