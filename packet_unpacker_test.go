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
	var (
		unpacker *packetUnpacker
		hdr      *wire.ExtendedHeader
		aead     *MockQuicAEAD
	)

	BeforeEach(func() {
		aead = NewMockQuicAEAD(mockCtrl)
		hdr = &wire.ExtendedHeader{
			PacketNumber:    10,
			PacketNumberLen: 1,
			Raw:             []byte{0x04, 0x4c, 0x01},
		}
		unpacker = newPacketUnpacker(aead, protocol.VersionWhatever).(*packetUnpacker)
	})

	It("errors if the packet doesn't contain any payload", func() {
		data := []byte("foobar")
		aead.EXPECT().Open1RTT(gomock.Any(), []byte("foobar"), hdr.PacketNumber, hdr.Raw).Return([]byte{}, nil)
		_, err := unpacker.Unpack(hdr, data)
		Expect(err).To(MatchError(qerr.MissingPayload))
	})

	It("opens Initial packets", func() {
		hdr.IsLongHeader = true
		hdr.Type = protocol.PacketTypeInitial
		aead.EXPECT().OpenInitial(gomock.Any(), gomock.Any(), hdr.PacketNumber, hdr.Raw).Return([]byte{0}, nil)
		packet, err := unpacker.Unpack(hdr, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionInitial))
	})

	It("opens Handshake packets", func() {
		hdr.IsLongHeader = true
		hdr.Type = protocol.PacketTypeHandshake
		aead.EXPECT().OpenHandshake(gomock.Any(), gomock.Any(), hdr.PacketNumber, hdr.Raw).Return([]byte{0}, nil)
		packet, err := unpacker.Unpack(hdr, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionHandshake))
	})

	It("returns the error when unpacking fails", func() {
		hdr.IsLongHeader = true
		hdr.Type = protocol.PacketTypeHandshake
		aead.EXPECT().OpenHandshake(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("test err"))
		_, err := unpacker.Unpack(hdr, nil)
		Expect(err).To(MatchError(qerr.Error(qerr.DecryptionFailure, "test err")))
	})

	It("decodes the packet number", func() {
		firstHdr := &wire.ExtendedHeader{
			PacketNumber:    0x1337,
			PacketNumberLen: 2,
		}
		aead.EXPECT().Open1RTT(gomock.Any(), gomock.Any(), firstHdr.PacketNumber, gomock.Any()).Return([]byte{0}, nil)
		packet, err := unpacker.Unpack(firstHdr, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.packetNumber).To(Equal(protocol.PacketNumber(0x1337)))
		// the real packet number is 0x1338, but only the last byte is sent
		secondHdr := &wire.ExtendedHeader{
			PacketNumber:    0x38,
			PacketNumberLen: 1,
		}
		// expect the call with the decoded packet number
		aead.EXPECT().Open1RTT(gomock.Any(), gomock.Any(), protocol.PacketNumber(0x1338), gomock.Any()).Return([]byte{0}, nil)
		packet, err = unpacker.Unpack(secondHdr, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.packetNumber).To(Equal(protocol.PacketNumber(0x1338)))
	})

	It("unpacks the frames", func() {
		buf := &bytes.Buffer{}
		(&wire.PingFrame{}).Write(buf, protocol.VersionWhatever)
		(&wire.DataBlockedFrame{}).Write(buf, protocol.VersionWhatever)
		aead.EXPECT().Open1RTT(gomock.Any(), gomock.Any(), hdr.PacketNumber, hdr.Raw).Return(buf.Bytes(), nil)
		packet, err := unpacker.Unpack(hdr, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{&wire.PingFrame{}, &wire.DataBlockedFrame{}}))
	})
})
