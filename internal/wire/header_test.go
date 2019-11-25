package wire

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Header Parsing", func() {
	appendVersion := func(data []byte, v protocol.VersionNumber) []byte {
		offset := len(data)
		data = append(data, []byte{0, 0, 0, 0}...)
		binary.BigEndian.PutUint32(data[offset:], uint32(v))
		return data
	}

	Context("Parsing the Connection ID", func() {
		It("parses the connection ID of a long header packet", func() {
			buf := &bytes.Buffer{}
			Expect((&ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
					SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6},
					Version:          versionIETFFrames,
				},
				PacketNumberLen: 2,
			}).Write(buf, versionIETFFrames)).To(Succeed())
			connID, err := ParseConnectionID(buf.Bytes(), 8)
			Expect(err).ToNot(HaveOccurred())
			Expect(connID).To(Equal(protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}))
		})

		It("parses the connection ID of a short header packet", func() {
			buf := &bytes.Buffer{}
			Expect((&ExtendedHeader{
				Header: Header{
					DestConnectionID: protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
				},
				PacketNumberLen: 2,
			}).Write(buf, versionIETFFrames)).To(Succeed())
			buf.Write([]byte("foobar"))
			connID, err := ParseConnectionID(buf.Bytes(), 4)
			Expect(err).ToNot(HaveOccurred())
			Expect(connID).To(Equal(protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}))
		})

		It("errors on EOF, for short header packets", func() {
			buf := &bytes.Buffer{}
			Expect((&ExtendedHeader{
				Header: Header{
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				},
				PacketNumberLen: 2,
			}).Write(buf, versionIETFFrames)).To(Succeed())
			data := buf.Bytes()[:buf.Len()-2] // cut the packet number
			_, err := ParseConnectionID(data, 8)
			Expect(err).ToNot(HaveOccurred())
			for i := 0; i < len(data); i++ {
				b := make([]byte, i)
				copy(b, data[:i])
				_, err := ParseConnectionID(b, 8)
				Expect(err).To(MatchError(io.EOF))
			}
		})

		It("errors on EOF, for long header packets", func() {
			buf := &bytes.Buffer{}
			Expect((&ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad, 0x13, 0x37},
					SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 8, 9},
					Version:          versionIETFFrames,
				},
				PacketNumberLen: 2,
			}).Write(buf, versionIETFFrames)).To(Succeed())
			data := buf.Bytes()[:buf.Len()-2] // cut the packet number
			_, err := ParseConnectionID(data, 8)
			Expect(err).ToNot(HaveOccurred())
			for i := 0; i < 1 /* first byte */ +4 /* version */ +1 /* conn ID lengths */ +6; /* dest conn ID */ i++ {
				b := make([]byte, i)
				copy(b, data[:i])
				_, err := ParseConnectionID(b, 8)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("Identifying Version Negotiation Packets", func() {
		It("identifies version negotiation packets", func() {
			Expect(IsVersionNegotiationPacket([]byte{0x80 | 0x56, 0, 0, 0, 0})).To(BeTrue())
			Expect(IsVersionNegotiationPacket([]byte{0x56, 0, 0, 0, 0})).To(BeFalse())
			Expect(IsVersionNegotiationPacket([]byte{0x80, 1, 0, 0, 0})).To(BeFalse())
			Expect(IsVersionNegotiationPacket([]byte{0x80, 0, 1, 0, 0})).To(BeFalse())
			Expect(IsVersionNegotiationPacket([]byte{0x80, 0, 0, 1, 0})).To(BeFalse())
			Expect(IsVersionNegotiationPacket([]byte{0x80, 0, 0, 0, 1})).To(BeFalse())
		})

		It("returns false on EOF", func() {
			vnp := []byte{0x80, 0, 0, 0, 0}
			for i := range vnp {
				Expect(IsVersionNegotiationPacket(vnp[:i])).To(BeFalse())
			}
		})
	})

	Context("Version Negotiation Packets", func() {
		It("parses", func() {
			srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
			destConnID := protocol.ConnectionID{9, 8, 7, 6, 5, 4, 3, 2, 1}
			versions := []protocol.VersionNumber{0x22334455, 0x33445566}
			vnp, err := ComposeVersionNegotiation(destConnID, srcConnID, versions)
			Expect(err).ToNot(HaveOccurred())
			Expect(IsVersionNegotiationPacket(vnp)).To(BeTrue())
			hdr, _, rest, err := ParsePacket(vnp, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.DestConnectionID).To(Equal(destConnID))
			Expect(hdr.SrcConnectionID).To(Equal(srcConnID))
			Expect(hdr.IsLongHeader).To(BeTrue())
			Expect(hdr.Version).To(BeZero())
			for _, v := range versions {
				Expect(hdr.SupportedVersions).To(ContainElement(v))
			}
			Expect(rest).To(BeEmpty())
		})

		It("errors if it contains versions of the wrong length", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			versions := []protocol.VersionNumber{0x22334455, 0x33445566}
			data, err := ComposeVersionNegotiation(connID, connID, versions)
			Expect(err).ToNot(HaveOccurred())
			_, _, _, err = ParsePacket(data[:len(data)-2], 0)
			Expect(err).To(MatchError("Version Negotiation packet has a version list with an invalid length"))
		})

		It("errors if the version list is empty", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			versions := []protocol.VersionNumber{0x22334455}
			data, err := ComposeVersionNegotiation(connID, connID, versions)
			Expect(err).ToNot(HaveOccurred())
			// remove 8 bytes (two versions), since ComposeVersionNegotiation also added a reserved version number
			data = data[:len(data)-8]
			_, _, _, err = ParsePacket(data, 0)
			Expect(err).To(MatchError("Version Negotiation packet has empty version list"))
		})
	})

	Context("Long Headers", func() {
		It("parses a Long Header", func() {
			destConnID := protocol.ConnectionID{9, 8, 7, 6, 5, 4, 3, 2, 1}
			srcConnID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
			data := []byte{0xc0 ^ 0x3}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x9) // dest conn id length
			data = append(data, destConnID...)
			data = append(data, 0x4) // src conn id length
			data = append(data, srcConnID...)
			data = append(data, encodeVarInt(6)...)  // token length
			data = append(data, []byte("foobar")...) // token
			data = append(data, encodeVarInt(10)...) // length
			hdrLen := len(data)
			data = append(data, []byte{0, 0, 0xbe, 0xef}...) // packet number
			data = append(data, []byte("foobar")...)
			Expect(IsVersionNegotiationPacket(data)).To(BeFalse())

			hdr, pdata, rest, err := ParsePacket(data, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(pdata).To(Equal(data))
			Expect(hdr.IsLongHeader).To(BeTrue())
			Expect(hdr.DestConnectionID).To(Equal(destConnID))
			Expect(hdr.SrcConnectionID).To(Equal(srcConnID))
			Expect(hdr.Type).To(Equal(protocol.PacketTypeInitial))
			Expect(hdr.Token).To(Equal([]byte("foobar")))
			Expect(hdr.Length).To(Equal(protocol.ByteCount(10)))
			Expect(hdr.Version).To(Equal(versionIETFFrames))
			Expect(rest).To(BeEmpty())
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.PacketNumber).To(Equal(protocol.PacketNumber(0xbeef)))
			Expect(extHdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
			Expect(b.Len()).To(Equal(6)) // foobar
			Expect(hdr.ParsedLen()).To(BeEquivalentTo(hdrLen))
		})

		It("errors if 0x40 is not set", func() {
			data := []byte{
				0x80 | 0x2<<4,
				0x11,                   // connection ID lengths
				0xde, 0xca, 0xfb, 0xad, // dest conn ID
				0xde, 0xad, 0xbe, 0xef, // src conn ID
			}
			_, _, _, err := ParsePacket(data, 0)
			Expect(err).To(MatchError("not a QUIC packet"))
		})

		It("stops parsing when encountering an unsupported version", func() {
			data := []byte{
				0xc0,
				0xde, 0xad, 0xbe, 0xef,
				0x8,                                    // dest conn ID len
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, // dest conn ID
				0x8,                                    // src conn ID len
				0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, // src conn ID
				'f', 'o', 'o', 'b', 'a', 'r', // unspecified bytes
			}
			hdr, _, rest, err := ParsePacket(data, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeTrue())
			Expect(hdr.Version).To(Equal(protocol.VersionNumber(0xdeadbeef)))
			Expect(hdr.DestConnectionID).To(Equal(protocol.ConnectionID{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}))
			Expect(hdr.SrcConnectionID).To(Equal(protocol.ConnectionID{0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1}))
			Expect(rest).To(BeEmpty())
		})

		It("parses a Long Header without a destination connection ID", func() {
			data := []byte{0xc0 ^ 0x1<<4}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x0)                               // dest conn ID len
			data = append(data, 0x4)                               // src conn ID len
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef}...) // source connection ID
			data = append(data, encodeVarInt(0)...)                // length
			data = append(data, []byte{0xde, 0xca, 0xfb, 0xad}...)
			hdr, _, _, err := ParsePacket(data, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketType0RTT))
			Expect(hdr.SrcConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}))
			Expect(hdr.DestConnectionID).To(BeEmpty())
		})

		It("parses a Long Header without a source connection ID", func() {
			data := []byte{0xc0 ^ 0x2<<4}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0xa)                                      // dest conn ID len
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // dest connection ID
			data = append(data, 0x0)                                      // src conn ID len
			data = append(data, encodeVarInt(0)...)                       // length
			data = append(data, []byte{0xde, 0xca, 0xfb, 0xad}...)
			hdr, _, _, err := ParsePacket(data, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.SrcConnectionID).To(BeEmpty())
			Expect(hdr.DestConnectionID).To(Equal(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
		})

		It("parses a Long Header with a 2 byte packet number", func() {
			data := []byte{0xc0 ^ 0x1}
			data = appendVersion(data, versionIETFFrames) // version number
			data = append(data, []byte{0x0, 0x0}...)      // connection ID lengths
			data = append(data, encodeVarInt(0)...)       // token length
			data = append(data, encodeVarInt(0)...)       // length
			data = append(data, []byte{0x1, 0x23}...)

			hdr, _, _, err := ParsePacket(data, 0)
			Expect(err).ToNot(HaveOccurred())
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
			data = append(data, []byte{0x0, 0x0}...)                      // dest and src conn ID lengths
			data = append(data, 0xa)                                      // orig dest conn ID len
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // source connection ID
			data = append(data, []byte{'f', 'o', 'o', 'b', 'a', 'r'}...)  // token
			hdr, pdata, rest, err := ParsePacket(data, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketTypeRetry))
			Expect(hdr.OrigDestConnectionID).To(Equal(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
			Expect(hdr.Token).To(Equal([]byte("foobar")))
			Expect(pdata).To(Equal(data))
			Expect(rest).To(BeEmpty())
		})

		It("errors if the token length is too large", func() {
			data := []byte{0xc0 ^ 0x1}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x0)                   // connection ID lengths
			data = append(data, encodeVarInt(4)...)    // token length: 4 bytes (1 byte too long)
			data = append(data, encodeVarInt(0x42)...) // length, 1 byte
			data = append(data, []byte{0x12, 0x34}...) // packet number

			_, _, _, err := ParsePacket(data, 0)
			Expect(err).To(MatchError(io.EOF))
		})

		It("errors if the 5th or 6th bit are set", func() {
			data := []byte{0xc0 | 0x2<<4 | 0x8 /* set the 5th bit */ | 0x1 /* 2 byte packet number */}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, []byte{0x0, 0x0}...)   // connection ID lengths
			data = append(data, encodeVarInt(2)...)    // length
			data = append(data, []byte{0x12, 0x34}...) // packet number
			hdr, _, _, err := ParsePacket(data, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketTypeHandshake))
			extHdr, err := hdr.ParseExtended(bytes.NewReader(data), versionIETFFrames)
			Expect(err).To(MatchError(ErrInvalidReservedBits))
			Expect(extHdr).ToNot(BeNil())
			Expect(extHdr.PacketNumber).To(Equal(protocol.PacketNumber(0x1234)))
		})

		It("errors on EOF, when parsing the header", func() {
			data := []byte{0xc0 ^ 0x2<<4}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x8)                                                       // dest conn ID len
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}...) // dest conn ID
			data = append(data, 0x8)                                                       // src conn ID len
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}...) // src conn ID
			for i := 0; i < len(data); i++ {
				_, _, _, err := ParsePacket(data[:i], 0)
				Expect(err).To(Equal(io.EOF))
			}
		})

		It("errors on EOF, when parsing the extended header", func() {
			data := []byte{0xc0 | 0x2<<4 | 0x3}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, []byte{0x0, 0x0}...) // connection ID lengths
			data = append(data, encodeVarInt(0)...)  // length
			hdrLen := len(data)
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef}...) // packet number
			for i := hdrLen; i < len(data); i++ {
				data = data[:i]
				hdr, _, _, err := ParsePacket(data, 0)
				Expect(err).ToNot(HaveOccurred())
				b := bytes.NewReader(data)
				_, err = hdr.ParseExtended(b, versionIETFFrames)
				Expect(err).To(Equal(io.EOF))
			}
		})

		It("errors on EOF, for a Retry packet", func() {
			data := []byte{0xc0 ^ 0x3<<4}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, []byte{0x0, 0x0}...)                      // connection ID lengths
			data = append(data, 0xa)                                      // Orig Destination Connection ID length
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // source connection ID
			hdrLen := len(data)
			for i := hdrLen; i < len(data); i++ {
				data = data[:i]
				hdr, _, _, err := ParsePacket(data, 0)
				Expect(err).ToNot(HaveOccurred())
				b := bytes.NewReader(data)
				_, err = hdr.ParseExtended(b, versionIETFFrames)
				Expect(err).To(Equal(io.EOF))
			}
		})

		Context("coalesced packets", func() {
			It("cuts packets", func() {
				buf := &bytes.Buffer{}
				hdr := Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
					Length:           2 + 6,
					Version:          versionIETFFrames,
				}
				Expect((&ExtendedHeader{
					Header:          hdr,
					PacketNumber:    0x1337,
					PacketNumberLen: 2,
				}).Write(buf, versionIETFFrames)).To(Succeed())
				hdrRaw := append([]byte{}, buf.Bytes()...)
				buf.Write([]byte("foobar")) // payload of the first packet
				buf.Write([]byte("raboof")) // second packet
				parsedHdr, data, rest, err := ParsePacket(buf.Bytes(), 4)
				Expect(err).ToNot(HaveOccurred())
				Expect(parsedHdr.Type).To(Equal(hdr.Type))
				Expect(parsedHdr.DestConnectionID).To(Equal(hdr.DestConnectionID))
				Expect(data).To(Equal(append(hdrRaw, []byte("foobar")...)))
				Expect(rest).To(Equal([]byte("raboof")))
			})
			It("errors on packets that are smaller than the length in the packet header, for too small packet number", func() {
				buf := &bytes.Buffer{}
				Expect((&ExtendedHeader{
					Header: Header{
						IsLongHeader:     true,
						Type:             protocol.PacketTypeInitial,
						DestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
						Length:           3,
						Version:          versionIETFFrames,
					},
					PacketNumber:    0x1337,
					PacketNumberLen: 2,
				}).Write(buf, versionIETFFrames)).To(Succeed())
				_, _, _, err := ParsePacket(buf.Bytes(), 4)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("packet length (2 bytes) is smaller than the expected length (3 bytes)"))
			})

			It("errors on packets that are smaller than the length in the packet header, for too small payload", func() {
				buf := &bytes.Buffer{}
				Expect((&ExtendedHeader{
					Header: Header{
						IsLongHeader:     true,
						Type:             protocol.PacketTypeInitial,
						DestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
						Length:           1000,
						Version:          versionIETFFrames,
					},
					PacketNumber:    0x1337,
					PacketNumberLen: 2,
				}).Write(buf, versionIETFFrames)).To(Succeed())
				buf.Write(make([]byte, 500-2 /* for packet number length */))
				_, _, _, err := ParsePacket(buf.Bytes(), 4)
				Expect(err).To(MatchError("packet length (500 bytes) is smaller than the expected length (1000 bytes)"))
			})
		})
	})

	Context("Short Headers", func() {
		It("reads a Short Header with a 8 byte connection ID", func() {
			connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}
			data := append([]byte{0x40}, connID...)
			data = append(data, 0x42) // packet number
			Expect(IsVersionNegotiationPacket(data)).To(BeFalse())

			hdr, pdata, rest, err := ParsePacket(data, 8)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeFalse())
			Expect(hdr.DestConnectionID).To(Equal(connID))
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.KeyPhase).To(Equal(protocol.KeyPhaseZero))
			Expect(extHdr.DestConnectionID).To(Equal(connID))
			Expect(extHdr.SrcConnectionID).To(BeEmpty())
			Expect(extHdr.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
			Expect(pdata).To(Equal(data))
			Expect(rest).To(BeEmpty())
		})

		It("errors if 0x40 is not set", func() {
			connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}
			data := append([]byte{0x0}, connID...)
			_, _, _, err := ParsePacket(data, 8)
			Expect(err).To(MatchError("not a QUIC packet"))
		})

		It("errors if the 4th or 5th bit are set", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5}
			data := append([]byte{0x40 | 0x10 /* set the 4th bit */}, connID...)
			data = append(data, 0x42) // packet number
			hdr, _, _, err := ParsePacket(data, 5)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeFalse())
			extHdr, err := hdr.ParseExtended(bytes.NewReader(data), versionIETFFrames)
			Expect(err).To(MatchError(ErrInvalidReservedBits))
			Expect(extHdr).ToNot(BeNil())
			Expect(extHdr.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
		})

		It("reads a Short Header with a 5 byte connection ID", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5}
			data := append([]byte{0x40}, connID...)
			data = append(data, 0x42) // packet number
			hdr, pdata, rest, err := ParsePacket(data, 5)
			Expect(err).ToNot(HaveOccurred())
			Expect(pdata).To(HaveLen(len(data)))
			Expect(hdr.IsLongHeader).To(BeFalse())
			Expect(hdr.DestConnectionID).To(Equal(connID))
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.KeyPhase).To(Equal(protocol.KeyPhaseZero))
			Expect(extHdr.DestConnectionID).To(Equal(connID))
			Expect(extHdr.SrcConnectionID).To(BeEmpty())
			Expect(rest).To(BeEmpty())
		})

		It("reads the Key Phase Bit", func() {
			data := []byte{
				0x40 ^ 0x4,
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // connection ID
			}
			data = append(data, 11) // packet number
			hdr, _, _, err := ParsePacket(data, 6)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeFalse())
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.KeyPhase).To(Equal(protocol.KeyPhaseOne))
			Expect(b.Len()).To(BeZero())
		})

		It("reads a header with a 2 byte packet number", func() {
			data := []byte{
				0x40 | 0x1,
				0xde, 0xad, 0xbe, 0xef, // connection ID
			}
			data = append(data, []byte{0x13, 0x37}...) // packet number
			hdr, _, _, err := ParsePacket(data, 4)
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
			hdr, _, _, err := ParsePacket(data, 10)
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
				_, _, _, err := ParsePacket(data, 8)
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
				hdr, _, _, err := ParsePacket(data, 6)
				Expect(err).ToNot(HaveOccurred())
				_, err = hdr.ParseExtended(bytes.NewReader(data), versionIETFFrames)
				Expect(err).To(Equal(io.EOF))
			}
		})
	})

	It("tells its packet type for logging", func() {
		Expect((&Header{IsLongHeader: true, Type: protocol.PacketTypeHandshake}).PacketType()).To(Equal("Handshake"))
		Expect((&Header{}).PacketType()).To(Equal("1-RTT"))
	})
})
