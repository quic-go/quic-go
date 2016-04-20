package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/crypto"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet unpacker", func() {
	var (
		unpacker *packetUnpacker
		hdr      *PublicHeader
		hdrBin   []byte
		aead     crypto.AEAD
		r        *bytes.Reader
	)

	BeforeEach(func() {
		aead = &crypto.NullAEAD{}
		hdr = &PublicHeader{
			PacketNumber: 1,
		}
		hdrBin = []byte{0x04, 0x4c, 0x01}
		unpacker = &packetUnpacker{aead: aead}
		r = nil
	})

	setReader := func(data []byte) {
		var b bytes.Buffer
		b.Write(aead.Seal(0, hdrBin, data))
		r = bytes.NewReader(b.Bytes())
	}

	It("unpacks empty packets", func() {
		setReader([]byte{0x01})
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.entropyBit).To(BeTrue())
		Expect(packet.frames).To(HaveLen(0))
	})
})
