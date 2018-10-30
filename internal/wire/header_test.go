package wire

import (
	"bytes"
	"log"
	"os"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Header", func() {
	const versionIETFHeader = protocol.VersionTLS // a QUIC version that uses the IETF Header format

	Context("Writing", func() {
		var buf *bytes.Buffer

		BeforeEach(func() {
			buf = &bytes.Buffer{}
		})

		appendPacketNumber := func(data []byte, pn protocol.PacketNumber, pnLen protocol.PacketNumberLen) []byte {
			buf := &bytes.Buffer{}
			utils.WriteVarIntPacketNumber(buf, pn, pnLen)
			return append(data, buf.Bytes()...)
		}

		Context("Long Header", func() {
			srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}

			It("writes", func() {
				err := (&Header{
					IsLongHeader:     true,
					Type:             0x5,
					DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
					SrcConnectionID:  protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad, 0x0, 0x0, 0x13, 0x37},
					PayloadLen:       0xcafe,
					PacketNumber:     0xdecaf,
					PacketNumberLen:  protocol.PacketNumberLen4,
					Version:          0x1020304,
				}).Write(buf, protocol.PerspectiveServer, versionIETFHeader)
				Expect(err).ToNot(HaveOccurred())
				expected := []byte{
					0x80 ^ 0x5,
					0x1, 0x2, 0x3, 0x4, // version number
					0x35,                               // connection ID lengths
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // dest connection ID
					0xde, 0xca, 0xfb, 0xad, 0x0, 0x0, 0x13, 0x37, // source connection ID
				}
				expected = append(expected, encodeVarInt(0xcafe)...) // payload length
				expected = appendPacketNumber(expected, 0xdecaf, protocol.PacketNumberLen4)
				Expect(buf.Bytes()).To(Equal(expected))
			})

			It("refuses to write a header with a too short connection ID", func() {
				err := (&Header{
					IsLongHeader:     true,
					Type:             0x5,
					SrcConnectionID:  srcConnID,
					DestConnectionID: protocol.ConnectionID{1, 2, 3}, // connection IDs must be at least 4 bytes long
					PacketNumber:     0xdecafbad,
					PacketNumberLen:  protocol.PacketNumberLen4,
					Version:          0x1020304,
				}).Write(buf, protocol.PerspectiveServer, versionIETFHeader)
				Expect(err).To(MatchError("invalid connection ID length: 3 bytes"))
			})

			It("refuses to write a header with a too long connection ID", func() {
				err := (&Header{
					IsLongHeader:     true,
					Type:             0x5,
					SrcConnectionID:  srcConnID,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}, // connection IDs must be at most 18 bytes long
					PacketNumber:     0xdecafbad,
					PacketNumberLen:  protocol.PacketNumberLen4,
					Version:          0x1020304,
				}).Write(buf, protocol.PerspectiveServer, versionIETFHeader)
				Expect(err).To(MatchError("invalid connection ID length: 19 bytes"))
			})

			It("writes a header with an 18 byte connection ID", func() {
				err := (&Header{
					IsLongHeader:     true,
					Type:             0x5,
					SrcConnectionID:  srcConnID,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}, // connection IDs must be at most 18 bytes long
					PacketNumber:     0xdecafbad,
					PacketNumberLen:  protocol.PacketNumberLen4,
					Version:          0x1020304,
				}).Write(buf, protocol.PerspectiveServer, versionIETFHeader)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(ContainSubstring(string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18})))
			})

			It("writes an Initial containing a token", func() {
				token := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
				err := (&Header{
					IsLongHeader:    true,
					Type:            protocol.PacketTypeInitial,
					Token:           token,
					PacketNumber:    0xdecafbad,
					PacketNumberLen: protocol.PacketNumberLen4,
					Version:         0x1020304,
				}).Write(buf, protocol.PerspectiveServer, versionIETFHeader)
				Expect(err).ToNot(HaveOccurred())
				expectedSubstring := append(encodeVarInt(uint64(len(token))), token...)
				Expect(buf.Bytes()).To(ContainSubstring(string(expectedSubstring)))
			})

			It("writes a Retry packet", func() {
				token := []byte("Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.")
				err := (&Header{
					IsLongHeader:         true,
					Type:                 protocol.PacketTypeRetry,
					Token:                token,
					OrigDestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9},
					Version:              0x1020304,
				}).Write(buf, protocol.PerspectiveServer, versionIETFHeader)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()[:6]).To(Equal([]byte{
					0x80 ^ uint8(protocol.PacketTypeRetry),
					0x1, 0x2, 0x3, 0x4, // version number
					0x0, // connection ID lengths))
				}))
				Expect(buf.Bytes()[6] & 0xf).To(Equal(uint8(6)))
				Expect(buf.Bytes()[7 : 7+9]).To(Equal([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9})) // Orig Dest Connection ID
				Expect(buf.Bytes()[7+9:]).To(Equal(token))
			})

			It("refuses to write a Retry packet with an invalid Orig Destination Connection ID length", func() {
				err := (&Header{
					IsLongHeader:         true,
					Type:                 protocol.PacketTypeRetry,
					Token:                []byte("foobar"),
					OrigDestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}, // connection IDs must be at most 18 bytes long
					Version:              0x1020304,
				}).Write(buf, protocol.PerspectiveServer, versionIETFHeader)
				Expect(err).To(MatchError("invalid connection ID length: 19 bytes"))
			})
		})

		Context("short header", func() {
			It("writes a header with connection ID", func() {
				err := (&Header{
					DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
					PacketNumberLen:  protocol.PacketNumberLen1,
					PacketNumber:     0x42,
				}).Write(buf, protocol.PerspectiveClient, versionIETFHeader)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x30,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0x42, // packet number
				}))
			})

			It("writes a header without connection ID", func() {
				err := (&Header{
					PacketNumberLen: protocol.PacketNumberLen1,
					PacketNumber:    0x42,
				}).Write(buf, protocol.PerspectiveClient, versionIETFHeader)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x30,
					0x42, // packet number
				}))
			})

			It("writes a header with a 2 byte packet number", func() {
				err := (&Header{
					PacketNumberLen: protocol.PacketNumberLen2,
					PacketNumber:    0x765,
				}).Write(buf, protocol.PerspectiveClient, versionIETFHeader)
				Expect(err).ToNot(HaveOccurred())
				expected := []byte{0x30}
				expected = appendPacketNumber(expected, 0x765, protocol.PacketNumberLen2)
				Expect(buf.Bytes()).To(Equal(expected))
			})

			It("writes a header with a 4 byte packet number", func() {
				err := (&Header{
					PacketNumberLen: protocol.PacketNumberLen4,
					PacketNumber:    0x123456,
				}).Write(buf, protocol.PerspectiveServer, versionIETFHeader)
				Expect(err).ToNot(HaveOccurred())
				expected := []byte{0x30}
				expected = appendPacketNumber(expected, 0x123456, protocol.PacketNumberLen4)
				Expect(buf.Bytes()).To(Equal(expected))
			})

			It("errors when given an invalid packet number length", func() {
				err := (&Header{
					PacketNumberLen: 3,
					PacketNumber:    0xdecafbad,
				}).Write(buf, protocol.PerspectiveClient, versionIETFHeader)
				Expect(err).To(MatchError("invalid packet number length: 3"))
			})

			It("writes the Key Phase Bit", func() {
				err := (&Header{
					KeyPhase:        1,
					PacketNumberLen: protocol.PacketNumberLen1,
					PacketNumber:    0x42,
				}).Write(buf, protocol.PerspectiveClient, versionIETFHeader)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x30 | 0x40,
					0x42, // packet number
				}))
			})
		})
	})

	Context("getting the length", func() {
		var buf *bytes.Buffer

		BeforeEach(func() {
			buf = &bytes.Buffer{}
		})

		It("has the right length for the Long Header, for a short payload length", func() {
			h := &Header{
				IsLongHeader:     true,
				PayloadLen:       1,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				PacketNumberLen:  protocol.PacketNumberLen1,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* conn ID len */ + 8 /* dest conn id */ + 8 /* src conn id */ + 1 /* short payload len */ + 1 /* packet number */
			Expect(h.GetLength(versionIETFHeader)).To(BeEquivalentTo(expectedLen))
			err := h.Write(buf, protocol.PerspectiveClient, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(expectedLen))
		})

		It("has the right length for the Long Header, for a long payload length", func() {
			h := &Header{
				IsLongHeader:     true,
				PayloadLen:       1500,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				PacketNumberLen:  protocol.PacketNumberLen2,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* conn ID len */ + 8 /* dest conn id */ + 8 /* src conn id */ + 2 /* long payload len */ + 2 /* packet number */
			Expect(h.GetLength(versionIETFHeader)).To(BeEquivalentTo(expectedLen))
			err := h.Write(buf, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(expectedLen))
		})

		It("has the right length for an Initial not containing a Token", func() {
			h := &Header{
				Type:             protocol.PacketTypeInitial,
				IsLongHeader:     true,
				PayloadLen:       1500,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4},
				PacketNumberLen:  protocol.PacketNumberLen2,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* conn ID len */ + 8 /* dest conn id */ + 4 /* src conn id */ + 1 /* token length */ + 2 /* long payload len */ + 2 /* packet number */
			Expect(h.GetLength(versionIETFHeader)).To(BeEquivalentTo(expectedLen))
			err := h.Write(buf, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(expectedLen))
		})

		It("has the right length for an Initial containing a Token", func() {
			h := &Header{
				Type:             protocol.PacketTypeInitial,
				IsLongHeader:     true,
				PayloadLen:       1500,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4},
				PacketNumberLen:  protocol.PacketNumberLen2,
				Token:            []byte("foo"),
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* conn ID len */ + 8 /* dest conn id */ + 4 /* src conn id */ + 1 /* token length */ + 3 /* token */ + 2 /* long payload len */ + 2 /* packet number */
			Expect(h.GetLength(versionIETFHeader)).To(BeEquivalentTo(expectedLen))
			err := h.Write(buf, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(expectedLen))
		})

		It("has the right length for a Short Header containing a connection ID", func() {
			h := &Header{
				PacketNumberLen:  protocol.PacketNumberLen1,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			}
			Expect(h.GetLength(versionIETFHeader)).To(Equal(protocol.ByteCount(1 + 8 + 1)))
			err := h.Write(buf, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(10))
		})

		It("has the right length for a short header without a connection ID", func() {
			h := &Header{PacketNumberLen: protocol.PacketNumberLen1}
			Expect(h.GetLength(versionIETFHeader)).To(Equal(protocol.ByteCount(1 + 1)))
			err := h.Write(buf, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(2))
		})

		It("has the right length for a short header with a 2 byte packet number", func() {
			h := &Header{PacketNumberLen: protocol.PacketNumberLen2}
			Expect(h.GetLength(versionIETFHeader)).To(Equal(protocol.ByteCount(1 + 2)))
			err := h.Write(buf, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(3))
		})

		It("has the right length for a short header with a 5 byte packet number", func() {
			h := &Header{PacketNumberLen: protocol.PacketNumberLen4}
			Expect(h.GetLength(versionIETFHeader)).To(Equal(protocol.ByteCount(1 + 4)))
			err := h.Write(buf, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(5))
		})

		It("errors when given an invalid packet number length", func() {
			h := &Header{PacketNumberLen: 5}
			_, err := h.GetLength(versionIETFHeader)
			Expect(err).To(MatchError("invalid packet number length: 5"))
		})

	})

	Context("Logging", func() {
		var (
			buf    *bytes.Buffer
			logger utils.Logger
		)

		BeforeEach(func() {
			buf = &bytes.Buffer{}
			logger = utils.DefaultLogger
			logger.SetLogLevel(utils.LogLevelDebug)
			log.SetOutput(buf)
		})

		AfterEach(func() {
			log.SetOutput(os.Stdout)
		})

		It("logs version negotiation packets", func() {
			destConnID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}
			srcConnID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad, 0x013, 0x37, 0x13, 0x37}
			data, err := ComposeVersionNegotiation(destConnID, srcConnID, []protocol.VersionNumber{0x12345678, 0x87654321})
			Expect(err).ToNot(HaveOccurred())
			b := bytes.NewReader(data)
			iHdr, err := ParseInvariantHeader(b, 4)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := iHdr.Parse(b, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			hdr.Log(logger)
			Expect(buf.String()).To(ContainSubstring("VersionNegotiationPacket{DestConnectionID: 0xdeadbeefcafe1337, SrcConnectionID: 0xdecafbad13371337"))
			Expect(buf.String()).To(ContainSubstring("0x12345678"))
			Expect(buf.String()).To(ContainSubstring("0x87654321"))
		})

		It("logs Long Headers", func() {
			(&Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				PacketNumber:     0x1337,
				PacketNumberLen:  protocol.PacketNumberLen2,
				PayloadLen:       54321,
				DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
				SrcConnectionID:  protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad, 0x013, 0x37, 0x13, 0x37},
				Version:          0xfeed,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Handshake, DestConnectionID: 0xdeadbeefcafe1337, SrcConnectionID: 0xdecafbad13371337, PacketNumber: 0x1337, PacketNumberLen: 2, PayloadLen: 54321, Version: 0xfeed}"))
		})

		It("logs Initial Packets with a Token", func() {
			(&Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				Token:            []byte{0xde, 0xad, 0xbe, 0xef},
				PacketNumber:     0x42,
				PacketNumberLen:  protocol.PacketNumberLen2,
				PayloadLen:       100,
				DestConnectionID: protocol.ConnectionID{0xca, 0xfe, 0x13, 0x37},
				SrcConnectionID:  protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
				Version:          0xfeed,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Initial, DestConnectionID: 0xcafe1337, SrcConnectionID: 0xdecafbad, Token: 0xdeadbeef, PacketNumber: 0x42, PacketNumberLen: 2, PayloadLen: 100, Version: 0xfeed}"))
		})

		It("logs Initial Packets without a Token", func() {
			(&Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				PacketNumber:     0x42,
				PacketNumberLen:  protocol.PacketNumberLen2,
				PayloadLen:       100,
				DestConnectionID: protocol.ConnectionID{0xca, 0xfe, 0x13, 0x37},
				SrcConnectionID:  protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
				Version:          0xfeed,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Initial, DestConnectionID: 0xcafe1337, SrcConnectionID: 0xdecafbad, Token: (empty), PacketNumber: 0x42, PacketNumberLen: 2, PayloadLen: 100, Version: 0xfeed}"))
		})

		It("logs Initial Packets with a Token", func() {
			(&Header{
				IsLongHeader:         true,
				Type:                 protocol.PacketTypeRetry,
				DestConnectionID:     protocol.ConnectionID{0xca, 0xfe, 0x13, 0x37},
				SrcConnectionID:      protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
				OrigDestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
				Token:                []byte{0x12, 0x34, 0x56},
				Version:              0xfeed,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Retry, DestConnectionID: 0xcafe1337, SrcConnectionID: 0xdecafbad, Token: 0x123456, OrigDestConnectionID: 0xdeadbeef, Version: 0xfeed}"))
		})

		It("logs Short Headers containing a connection ID", func() {
			(&Header{
				KeyPhase:         1,
				PacketNumber:     0x1337,
				PacketNumberLen:  4,
				DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Short Header{DestConnectionID: 0xdeadbeefcafe1337, PacketNumber: 0x1337, PacketNumberLen: 4, KeyPhase: 1}"))
		})
	})
})
