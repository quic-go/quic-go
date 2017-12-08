package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packing and unpacking Initial packets", func() {
	var aead crypto.AEAD
	connID := protocol.ConnectionID(0x1337)
	ver := protocol.VersionTLS
	hdr := &wire.Header{
		IsLongHeader: true,
		Type:         protocol.PacketTypeRetry,
		PacketNumber: 0x42,
		ConnectionID: connID,
		Version:      ver,
	}

	BeforeEach(func() {
		var err error
		aead, err = crypto.NewNullAEAD(protocol.PerspectiveServer, connID, ver)
		Expect(err).ToNot(HaveOccurred())
		// set hdr.Raw
		buf := &bytes.Buffer{}
		err = hdr.Write(buf, protocol.PerspectiveServer, ver)
		Expect(err).ToNot(HaveOccurred())
		hdr.Raw = buf.Bytes()
	})

	Context("unpacking", func() {
		packPacket := func(frames []wire.Frame) []byte {
			buf := &bytes.Buffer{}
			err := hdr.Write(buf, protocol.PerspectiveClient, ver)
			Expect(err).ToNot(HaveOccurred())
			payloadStartIndex := buf.Len()
			aeadCl, err := crypto.NewNullAEAD(protocol.PerspectiveClient, connID, ver)
			for _, f := range frames {
				err := f.Write(buf, ver)
				Expect(err).ToNot(HaveOccurred())
			}
			raw := buf.Bytes()
			return aeadCl.Seal(raw[payloadStartIndex:payloadStartIndex], raw[payloadStartIndex:], hdr.PacketNumber, raw[:payloadStartIndex])
		}

		It("unpacks a packet", func() {
			f := &wire.StreamFrame{
				StreamID: 0,
				Data:     []byte("foobar"),
			}
			p := packPacket([]wire.Frame{f})
			frame, err := unpackInitialPacket(aead, hdr, p, ver)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(f))
		})

		It("rejects a packet that doesn't contain a STREAM_FRAME", func() {
			p := packPacket([]wire.Frame{&wire.PingFrame{}})
			_, err := unpackInitialPacket(aead, hdr, p, ver)
			Expect(err).To(MatchError("Packet doesn't contain a STREAM_FRAME"))
		})

		It("rejects a packet that has a STREAM_FRAME for the wrong stream", func() {
			f := &wire.StreamFrame{
				StreamID: 42,
				Data:     []byte("foobar"),
			}
			p := packPacket([]wire.Frame{f})
			_, err := unpackInitialPacket(aead, hdr, p, ver)
			Expect(err).To(MatchError("UnencryptedStreamData: received unencrypted stream data on stream 42"))
		})

		It("rejects a packet that has a STREAM_FRAME with a non-zero offset", func() {
			f := &wire.StreamFrame{
				StreamID: 0,
				Offset:   10,
				Data:     []byte("foobar"),
			}
			p := packPacket([]wire.Frame{f})
			_, err := unpackInitialPacket(aead, hdr, p, ver)
			Expect(err).To(MatchError("received stream data with non-zero offset"))
		})
	})

	Context("packing", func() {
		var unpacker *packetUnpacker

		BeforeEach(func() {
			aeadCl, err := crypto.NewNullAEAD(protocol.PerspectiveClient, connID, ver)
			Expect(err).ToNot(HaveOccurred())
			unpacker = &packetUnpacker{aead: &nullAEAD{aeadCl}, version: ver}
		})

		It("packs a packet", func() {
			f := &wire.StreamFrame{
				Data:   []byte("foobar"),
				FinBit: true,
			}
			data, err := packUnencryptedPacket(aead, hdr, f, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			packet, err := unpacker.Unpack(hdr.Raw, hdr, data[len(hdr.Raw):])
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})
	})
})
