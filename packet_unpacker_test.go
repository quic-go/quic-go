package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockAEAD struct {
	encLevelOpen protocol.EncryptionLevel
}

func (m *mockAEAD) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error) {
	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveClient, 0x1337, protocol.VersionWhatever)
	Expect(err).ToNot(HaveOccurred())
	res, err := nullAEAD.Open(dst, src, packetNumber, associatedData)
	return res, m.encLevelOpen, err
}
func (m *mockAEAD) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel) {
	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveServer, 0x1337, protocol.VersionWhatever)
	Expect(err).ToNot(HaveOccurred())
	return nullAEAD.Seal(dst, src, packetNumber, associatedData), protocol.EncryptionUnspecified
}

var _ quicAEAD = &mockAEAD{}

var _ = Describe("Packet unpacker", func() {
	var (
		unpacker *packetUnpacker
		hdr      *wire.Header
		hdrBin   []byte
		data     []byte
		buf      *bytes.Buffer
	)

	BeforeEach(func() {
		hdr = &wire.Header{
			PacketNumber:    10,
			PacketNumberLen: 1,
		}
		hdrBin = []byte{0x04, 0x4c, 0x01}
		unpacker = &packetUnpacker{aead: &mockAEAD{}}
		data = nil
		buf = &bytes.Buffer{}
	})

	setData := func(p []byte) {
		data, _ = unpacker.aead.(*mockAEAD).Seal(nil, p, 0, hdrBin)
	}

	It("errors if the packet doesn't contain any payload", func() {
		setData(nil)
		_, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).To(MatchError(qerr.MissingPayload))
	})

	It("saves the encryption level", func() {
		unpacker.version = versionGQUICFrames
		f := &wire.ConnectionCloseFrame{ReasonPhrase: "foo"}
		err := f.Write(buf, versionGQUICFrames)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionSecure
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionSecure))
	})
})
