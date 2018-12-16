package wire

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Header Parsing", func() {
	appendVersion := func(data []byte, v protocol.VersionNumber) []byte {
		offset := len(data)
		data = append(data, []byte{0, 0, 0, 0}...)
		binary.BigEndian.PutUint32(data[offset:], uint32(versionIETFFrames))
		return data
	}

	Context("Version Negotiation Packets", func() {
		It("parses", func() {
			srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
			destConnID := protocol.ConnectionID{9, 8, 7, 6, 5, 4, 3, 2, 1}
			versions := []protocol.VersionNumber{0x22334455, 0x33445566}
			data, err := ComposeVersionNegotiation(destConnID, srcConnID, versions)
			Expect(err).ToNot(HaveOccurred())
			b := bytes.NewReader(data)
			hdr, err := ParseHeader(b, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.DestConnectionID).To(Equal(destConnID))
			Expect(hdr.SrcConnectionID).To(Equal(srcConnID))
			Expect(hdr.IsLongHeader).To(BeTrue())
			Expect(hdr.IsVersionNegotiation()).To(BeTrue())
			Expect(hdr.Version).To(BeZero())
			for _, v := range versions {
				Expect(hdr.SupportedVersions).To(ContainElement(v))
			}
			Expect(b.Len()).To(BeZero())
		})

		It("errors if it contains versions of the wrong length", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			versions := []protocol.VersionNumber{0x22334455, 0x33445566}
			data, err := ComposeVersionNegotiation(connID, connID, versions)
			Expect(err).ToNot(HaveOccurred())
			data = data[:len(data)-2]
			_, err = ParseHeader(bytes.NewReader(data), 0)
			Expect(err).To(MatchError(qerr.InvalidVersionNegotiationPacket))
		})

		It("errors if the version list is empty", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			versions := []protocol.VersionNumber{0x22334455}
			data, err := ComposeVersionNegotiation(connID, connID, versions)
			Expect(err).ToNot(HaveOccurred())
			// remove 8 bytes (two versions), since ComposeVersionNegotiation also added a reserved version number
			data = data[:len(data)-8]
			_, err = ParseHeader(bytes.NewReader(data), 0)
			Expect(err).To(MatchError("InvalidVersionNegotiationPacket: empty version list"))
		})
	})

	Context("Long Headers", func() {
		It("parses a Long Header", func() {
			destConnID := protocol.ConnectionID{9, 8, 7, 6, 5, 4, 3, 2, 1}
			srcConnID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
			data := []byte{0xc0 ^ 0x3}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x61) // connection ID lengths
			data = append(data, destConnID...)
			data = append(data, srcConnID...)
			data = append(data, encodeVarInt(6)...)      // token length
			data = append(data, []byte("foobar")...)     // token
			data = append(data, encodeVarInt(0x1337)...) // length
			hdrLen := len(data)
			data = append(data, []byte{0, 0, 0xbe, 0xef}...)

			hdr, err := ParseHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeTrue())
			Expect(hdr.IsVersionNegotiation()).To(BeFalse())
			Expect(hdr.DestConnectionID).To(Equal(destConnID))
			Expect(hdr.SrcConnectionID).To(Equal(srcConnID))
			Expect(hdr.Type).To(Equal(protocol.PacketTypeInitial))
			Expect(hdr.Token).To(Equal([]byte("foobar")))
			Expect(hdr.Length).To(Equal(protocol.ByteCount(0x1337)))
			Expect(hdr.Version).To(Equal(versionIETFFrames))
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.PacketNumber).To(Equal(protocol.PacketNumber(0xbeef)))
			Expect(extHdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
			Expect(b.Len()).To(BeZero())
			Expect(hdr.ParsedLen()).To(BeEquivalentTo(hdrLen))
		})

		It("errors if 0x40 is not set", func() {
			data := []byte{
				0x80 | 0x2<<4,
				0x11,                   // connection ID lengths
				0xde, 0xca, 0xfb, 0xad, // dest conn ID
				0xde, 0xad, 0xbe, 0xef, // src conn ID
			}
			_, err := ParseHeader(bytes.NewReader(data), 0)
			Expect(err).To(MatchError("not a QUIC packet"))
		})

		It("stops parsing when encountering an unsupported version", func() {
			data := []byte{
				0xc0,
				0xde, 0xad, 0xbe, 0xef,
				0x55, // connection ID length
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
				0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1,
				'f', 'o', 'o', 'b', 'a', 'r', // unspecified bytes
			}
			b := bytes.NewReader(data)
			hdr, err := ParseHeader(b, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeTrue())
			Expect(hdr.Version).To(Equal(protocol.VersionNumber(0xdeadbeef)))
			Expect(hdr.DestConnectionID).To(Equal(protocol.ConnectionID{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}))
			Expect(hdr.SrcConnectionID).To(Equal(protocol.ConnectionID{0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1}))
			Expect(b.Len()).To(Equal(6))
		})

		It("parses a Long Header without a destination connection ID", func() {
			data := []byte{0xc0 ^ 0x1<<4}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x01)                              // connection ID lengths
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef}...) // source connection ID
			data = append(data, encodeVarInt(0x42)...)             // length
			data = append(data, []byte{0xde, 0xca, 0xfb, 0xad}...)
			hdr, err := ParseHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketType0RTT))
			Expect(hdr.SrcConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}))
			Expect(hdr.DestConnectionID).To(BeEmpty())
		})

		It("parses a Long Header without a source connection ID", func() {
			data := []byte{0xc0 ^ 0x2<<4}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x70)                                     // connection ID lengths
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // source connection ID
			data = append(data, encodeVarInt(0x42)...)                    // length
			data = append(data, []byte{0xde, 0xca, 0xfb, 0xad}...)
			hdr, err := ParseHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.SrcConnectionID).To(BeEmpty())
			Expect(hdr.DestConnectionID).To(Equal(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
		})

		It("parses a Long Header with a 2 byte packet number", func() {
			data := []byte{0xc0 ^ 0x1}
			data = appendVersion(data, versionIETFFrames) // version number
			data = append(data, 0x0)                      // connection ID lengths
			data = append(data, encodeVarInt(0)...)       // token length
			data = append(data, encodeVarInt(0x42)...)    // length
			data = append(data, []byte{0x1, 0x23}...)

			hdr, err := ParseHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Length).To(BeEquivalentTo(0x42))
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.PacketNumber).To(Equal(protocol.PacketNumber(0x123)))
			Expect(extHdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen2))
			Expect(b.Len()).To(BeZero())
		})

		It("parses a Retry packet", func() {
			data := []byte{0xc0 | 0x3<<4 | (10 - 3) /* connection ID length */}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x0)                                      // connection ID lengths
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // source connection ID
			data = append(data, []byte{'f', 'o', 'o', 'b', 'a', 'r'}...)  // token
			b := bytes.NewReader(data)
			hdr, err := ParseHeader(b, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketTypeRetry))
			Expect(hdr.OrigDestConnectionID).To(Equal(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
			Expect(hdr.Token).To(Equal([]byte("foobar")))
		})

		It("errors if the token length is too large", func() {
			data := []byte{0xc0 ^ 0x1}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x0)                   // connection ID lengths
			data = append(data, encodeVarInt(4)...)    // token length: 4 bytes (1 byte too long)
			data = append(data, encodeVarInt(0x42)...) // length, 1 byte
			data = append(data, []byte{0x12, 0x34}...) // packet number

			_, err := ParseHeader(bytes.NewReader(data), 0)
			Expect(err).To(MatchError(io.EOF))
		})

		It("errors if the 5th or 6th bit are set", func() {
			data := []byte{0xc0 | 0x2<<4 | 0x8 /* set the 5th bit */}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x0)                // connection ID lengths
			data = append(data, 0x42)               // packet number
			data = append(data, encodeVarInt(1)...) // length
			hdr, err := ParseHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketTypeHandshake))
			_, err = hdr.ParseExtended(bytes.NewReader(data), versionIETFFrames)
			Expect(err).To(MatchError("5th and 6th bit must be 0"))
		})

		It("errors on EOF, when parsing the header", func() {
			data := []byte{0xc0 ^ 0x2<<4}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x55)                                                      // connection ID lengths
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}...) // destination connection ID
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}...) // source connection ID
			for i := 0; i < len(data); i++ {
				_, err := ParseHeader(bytes.NewReader(data[:i]), 0)
				Expect(err).To(Equal(io.EOF))
			}
		})

		It("errors on EOF, when parsing the extended header", func() {
			data := []byte{0xc0 | 0x2<<4 | 0x3}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x0) // connection ID lengths
			data = append(data, encodeVarInt(0x1337)...)
			hdrLen := len(data)
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef}...) // packet number
			for i := hdrLen; i < len(data); i++ {
				data = data[:i]
				hdr, err := ParseHeader(bytes.NewReader(data), 0)
				Expect(err).ToNot(HaveOccurred())
				b := bytes.NewReader(data)
				_, err = hdr.ParseExtended(b, versionIETFFrames)
				Expect(err).To(Equal(io.EOF))
			}
		})

		It("errors on EOF, for a Retry packet", func() {
			data := []byte{0xc0 ^ 0x3<<4}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x0)                                      // connection ID lengths
			data = append(data, 0x97)                                     // Orig Destination Connection ID length
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // source connection ID
			hdrLen := len(data)
			for i := hdrLen; i < len(data); i++ {
				data = data[:i]
				hdr, err := ParseHeader(bytes.NewReader(data), 0)
				Expect(err).ToNot(HaveOccurred())
				b := bytes.NewReader(data)
				_, err = hdr.ParseExtended(b, versionIETFFrames)
				Expect(err).To(Equal(io.EOF))
			}
		})
	})

	Context("Short Headers", func() {
		It("reads a Short Header with a 8 byte connection ID", func() {
			connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}
			data := append([]byte{0x40}, connID...)
			data = append(data, 0x42) // packet number
			hdr, err := ParseHeader(bytes.NewReader(data), 8)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeFalse())
			Expect(hdr.IsVersionNegotiation()).To(BeFalse())
			Expect(hdr.DestConnectionID).To(Equal(connID))
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.KeyPhase).To(Equal(0))
			Expect(extHdr.DestConnectionID).To(Equal(connID))
			Expect(extHdr.SrcConnectionID).To(BeEmpty())
			Expect(extHdr.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors if 0x40 is not set", func() {
			connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}
			data := append([]byte{0x0}, connID...)
			_, err := ParseHeader(bytes.NewReader(data), 8)
			Expect(err).To(MatchError("not a QUIC packet"))
		})

		It("errors if the 4th or 5th bit are set", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5}
			data := append([]byte{0x40 | 0x10 /* set the 4th bit */}, connID...)
			hdr, err := ParseHeader(bytes.NewReader(data), 5)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeFalse())
			_, err = hdr.ParseExtended(bytes.NewReader(data), versionIETFFrames)
			Expect(err).To(MatchError("4th and 5th bit must be 0"))
		})

		It("reads a Short Header with a 5 byte connection ID", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5}
			data := append([]byte{0x40}, connID...)
			data = append(data, 0x42) // packet number
			hdr, err := ParseHeader(bytes.NewReader(data), 5)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeFalse())
			Expect(hdr.DestConnectionID).To(Equal(connID))
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.KeyPhase).To(Equal(0))
			Expect(extHdr.DestConnectionID).To(Equal(connID))
			Expect(extHdr.SrcConnectionID).To(BeEmpty())
			Expect(b.Len()).To(BeZero())
		})

		It("reads the Key Phase Bit", func() {
			data := []byte{
				0x40 ^ 0x4,
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // connection ID
			}
			data = append(data, 11) // packet number
			hdr, err := ParseHeader(bytes.NewReader(data), 6)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeFalse())
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.KeyPhase).To(Equal(1))
			Expect(b.Len()).To(BeZero())
		})

		It("reads a header with a 2 byte packet number", func() {
			data := []byte{
				0x40 | 0x1,
				0xde, 0xad, 0xbe, 0xef, // connection ID
			}
			data = append(data, []byte{0x13, 0x37}...) // packet number
			hdr, err := ParseHeader(bytes.NewReader(data), 4)
			Expect(err).ToNot(HaveOccurred())
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.IsLongHeader).To(BeFalse())
			Expect(extHdr.PacketNumber).To(Equal(protocol.PacketNumber(0x1337)))
			Expect(extHdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen2))
			Expect(b.Len()).To(BeZero())
		})

		It("reads a header with a 3 byte packet number", func() {
			data := []byte{
				0x40 | 0x2,
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x1, 0x2, 0x3, 0x4, // connection ID
			}
			data = append(data, []byte{0x99, 0xbe, 0xef}...) // packet number
			hdr, err := ParseHeader(bytes.NewReader(data), 10)
			Expect(err).ToNot(HaveOccurred())
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.IsLongHeader).To(BeFalse())
			Expect(extHdr.PacketNumber).To(Equal(protocol.PacketNumber(0x99beef)))
			Expect(extHdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen3))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOF, when parsing the header", func() {
			data := []byte{
				0x40 ^ 0x2,
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
			}
			for i := 0; i < len(data); i++ {
				data = data[:i]
				_, err := ParseHeader(bytes.NewReader(data), 8)
				Expect(err).To(Equal(io.EOF))
			}
		})

		It("errors on EOF, when parsing the extended header", func() {
			data := []byte{
				0x40 ^ 0x3,
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // connection ID
			}
			hdrLen := len(data)
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef}...) // packet number
			for i := hdrLen; i < len(data); i++ {
				data = data[:i]
				hdr, err := ParseHeader(bytes.NewReader(data), 6)
				Expect(err).ToNot(HaveOccurred())
				_, err = hdr.ParseExtended(bytes.NewReader(data), versionIETFFrames)
				Expect(err).To(Equal(io.EOF))
			}
		})
	})
})
