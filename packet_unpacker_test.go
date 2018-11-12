package quic

import (
	"bytes"

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
		hdr      *wire.Header
		aead     *MockQuicAEAD
	)

	BeforeEach(func() {
		aead = NewMockQuicAEAD(mockCtrl)
		hdr = &wire.Header{
			PacketNumber:    10,
			PacketNumberLen: 1,
			Raw:             []byte{0x04, 0x4c, 0x01},
		}
		unpacker = newPacketUnpacker(aead, protocol.VersionWhatever).(*packetUnpacker)
	})

	It("errors if the packet doesn't contain any payload", func() {
		data := []byte("foobar")
		aead.EXPECT().Open1RTT(gomock.Any(), []byte("foobar"), hdr.PacketNumber, hdr.Raw).Return([]byte{}, nil)
		_, err := unpacker.Unpack(hdr.Raw, hdr, data)
		Expect(err).To(MatchError(qerr.MissingPayload))
	})

	It("opens Initial packets", func() {
		hdr.IsLongHeader = true
		hdr.Type = protocol.PacketTypeInitial
		aead.EXPECT().OpenInitial(gomock.Any(), gomock.Any(), hdr.PacketNumber, hdr.Raw).Return([]byte{0}, nil)
		packet, err := unpacker.Unpack(hdr.Raw, hdr, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionInitial))
	})

	It("opens Handshake packets", func() {
		hdr.IsLongHeader = true
		hdr.Type = protocol.PacketTypeHandshake
		aead.EXPECT().OpenHandshake(gomock.Any(), gomock.Any(), hdr.PacketNumber, hdr.Raw).Return([]byte{0}, nil)
		packet, err := unpacker.Unpack(hdr.Raw, hdr, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionHandshake))
	})

	It("unpacks the frames", func() {
		buf := &bytes.Buffer{}
		(&wire.PingFrame{}).Write(buf, protocol.VersionWhatever)
		(&wire.DataBlockedFrame{}).Write(buf, protocol.VersionWhatever)
		aead.EXPECT().Open1RTT(gomock.Any(), gomock.Any(), hdr.PacketNumber, hdr.Raw).Return(buf.Bytes(), nil)
		packet, err := unpacker.Unpack(hdr.Raw, hdr, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{&wire.PingFrame{}, &wire.DataBlockedFrame{}}))
	})
})
