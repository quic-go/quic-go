package quic

import (
	"bytes"
	"errors"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Unpacker", func() {
	const version = protocol.VersionTLS
	var (
		unpacker *packetUnpacker
		aead     *MockQuicAEAD
		connID   = protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
	)

	getHeader := func(extHdr *wire.ExtendedHeader) (*wire.Header, []byte) {
		buf := &bytes.Buffer{}
		Expect(extHdr.Write(buf, protocol.VersionWhatever)).To(Succeed())
		hdr, err := wire.ParseHeader(bytes.NewReader(buf.Bytes()), connID.Len())
		Expect(err).ToNot(HaveOccurred())
		return hdr, buf.Bytes()
	}

	BeforeEach(func() {
		aead = NewMockQuicAEAD(mockCtrl)
		unpacker = newPacketUnpacker(aead, version).(*packetUnpacker)
	})

	It("errors if the packet doesn't contain any payload", func() {
		extHdr := &wire.ExtendedHeader{
			Header:          wire.Header{DestConnectionID: connID},
			PacketNumber:    42,
			PacketNumberLen: protocol.PacketNumberLen2,
		}
		hdr, hdrRaw := getHeader(extHdr)
		data := append(hdrRaw, []byte("foobar")...) // add some payload
		// return an empty (unencrypted) payload
		aead.EXPECT().Open1RTT(gomock.Any(), []byte("foobar"), extHdr.PacketNumber, hdrRaw).Return([]byte{}, nil)
		_, err := unpacker.Unpack(hdr, data)
		Expect(err).To(MatchError(qerr.MissingPayload))
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
		aead.EXPECT().OpenInitial(gomock.Any(), []byte("foobar"), extHdr.PacketNumber, hdrRaw).Return([]byte{0}, nil)
		packet, err := unpacker.Unpack(hdr, append(hdrRaw, []byte("foobar")...))
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionInitial))
	})

	It("opens Handshake packets", func() {
		extHdr := &wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				Length:           3 + 6, // packet number len + payload
				DestConnectionID: connID,
				Version:          version,
			},
			PacketNumber:    2,
			PacketNumberLen: 3,
		}
		hdr, hdrRaw := getHeader(extHdr)
		aead.EXPECT().OpenHandshake(gomock.Any(), gomock.Any(), extHdr.PacketNumber, hdrRaw).Return([]byte{0}, nil)
		packet, err := unpacker.Unpack(hdr, append(hdrRaw, []byte("foobar")...))
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionHandshake))
	})

	It("errors on packets that are smaller than the length in the packet header", func() {
		extHdr := &wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				Length:           1000,
				DestConnectionID: connID,
				Version:          version,
			},
			PacketNumberLen: protocol.PacketNumberLen2,
		}
		hdr, hdrRaw := getHeader(extHdr)
		data := append(hdrRaw, make([]byte, 500-2 /* for packet number length */)...)
		_, err := unpacker.Unpack(hdr, data)
		Expect(err).To(MatchError("packet length (500 bytes) is smaller than the expected length (1000 bytes)"))
	})

	It("errors when receiving a packet that has a length smaller than the packet number length", func() {
		extHdr := &wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				DestConnectionID: connID,
				Type:             protocol.PacketTypeHandshake,
				Length:           3,
				Version:          protocol.VersionTLS,
			},
			PacketNumberLen: protocol.PacketNumberLen4,
		}
		hdr, hdrRaw := getHeader(extHdr)
		_, err := unpacker.Unpack(hdr, hdrRaw)
		Expect(err).To(MatchError("packet length (3 bytes) shorter than packet number (4 bytes)"))
	})

	It("cuts packets to the right length", func() {
		pnLen := protocol.PacketNumberLen2
		extHdr := &wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				DestConnectionID: connID,
				Type:             protocol.PacketTypeHandshake,
				Length:           456,
				Version:          protocol.VersionTLS,
			},
			PacketNumberLen: pnLen,
		}
		payloadLen := 456 - int(pnLen)
		hdr, hdrRaw := getHeader(extHdr)
		data := append(hdrRaw, make([]byte, payloadLen)...)
		aead.EXPECT().OpenHandshake(gomock.Any(), gomock.Any(), extHdr.PacketNumber, hdrRaw).DoAndReturn(func(_, payload []byte, _ protocol.PacketNumber, _ []byte) ([]byte, error) {
			Expect(payload).To(HaveLen(payloadLen))
			return []byte{0}, nil
		})
		_, err := unpacker.Unpack(hdr, data)
		Expect(err).ToNot(HaveOccurred())
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
		aead.EXPECT().OpenHandshake(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("test err"))
		_, err := unpacker.Unpack(hdr, hdrRaw)
		Expect(err).To(MatchError(qerr.Error(qerr.DecryptionFailure, "test err")))
	})

	It("decodes the packet number", func() {
		firstHdr := &wire.ExtendedHeader{
			Header:          wire.Header{DestConnectionID: connID},
			PacketNumber:    0x1337,
			PacketNumberLen: 2,
		}
		aead.EXPECT().Open1RTT(gomock.Any(), gomock.Any(), firstHdr.PacketNumber, gomock.Any()).Return([]byte{0}, nil)
		packet, err := unpacker.Unpack(getHeader(firstHdr))
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.packetNumber).To(Equal(protocol.PacketNumber(0x1337)))
		// the real packet number is 0x1338, but only the last byte is sent
		secondHdr := &wire.ExtendedHeader{
			Header:          wire.Header{DestConnectionID: connID},
			PacketNumber:    0x38,
			PacketNumberLen: 1,
		}
		// expect the call with the decoded packet number
		aead.EXPECT().Open1RTT(gomock.Any(), gomock.Any(), protocol.PacketNumber(0x1338), gomock.Any()).Return([]byte{0}, nil)
		packet, err = unpacker.Unpack(getHeader(secondHdr))
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.packetNumber).To(Equal(protocol.PacketNumber(0x1338)))
	})

	It("unpacks the frames", func() {
		extHdr := &wire.ExtendedHeader{
			Header:          wire.Header{DestConnectionID: connID},
			PacketNumber:    0x1337,
			PacketNumberLen: 2,
		}
		buf := &bytes.Buffer{}
		(&wire.PingFrame{}).Write(buf, protocol.VersionWhatever)
		(&wire.DataBlockedFrame{}).Write(buf, protocol.VersionWhatever)
		hdr, hdrRaw := getHeader(extHdr)
		aead.EXPECT().Open1RTT(gomock.Any(), gomock.Any(), extHdr.PacketNumber, hdrRaw).Return(buf.Bytes(), nil)
		packet, err := unpacker.Unpack(hdr, append(hdrRaw, buf.Bytes()...))
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{&wire.PingFrame{}, &wire.DataBlockedFrame{}}))
	})
})
