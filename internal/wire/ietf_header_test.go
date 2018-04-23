package wire

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("IETF QUIC Header", func() {
	Context("parsing", func() {
		Context("Version Negotiation Packets", func() {
			It("parses", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				versions := []protocol.VersionNumber{0x22334455, 0x33445566}
				data, err := ComposeVersionNegotiation(connID, connID, versions)
				Expect(err).ToNot(HaveOccurred())
				b := bytes.NewReader(data)
				h, err := parseHeader(b, protocol.PerspectiveServer)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsVersionNegotiation).To(BeTrue())
				Expect(h.Version).To(BeZero())
				Expect(h.DestConnectionID).To(Equal(connID))
				Expect(h.SrcConnectionID).To(Equal(connID))
				for _, v := range versions {
					Expect(h.SupportedVersions).To(ContainElement(v))
				}
			})

			It("errors if it contains versions of the wrong length", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				versions := []protocol.VersionNumber{0x22334455, 0x33445566}
				data, err := ComposeVersionNegotiation(connID, connID, versions)
				Expect(err).ToNot(HaveOccurred())
				b := bytes.NewReader(data[:len(data)-2])
				_, err = parseHeader(b, protocol.PerspectiveServer)
				Expect(err).To(MatchError(qerr.InvalidVersionNegotiationPacket))
			})

			It("errors if the version list is empty", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				versions := []protocol.VersionNumber{0x22334455}
				data, err := ComposeVersionNegotiation(connID, connID, versions)
				Expect(err).ToNot(HaveOccurred())
				// remove 8 bytes (two versions), since ComposeVersionNegotiation also added a reserved version number
				_, err = parseHeader(bytes.NewReader(data[:len(data)-8]), protocol.PerspectiveServer)
				Expect(err).To(MatchError("InvalidVersionNegotiationPacket: empty version list"))
			})
		})

		Context("long headers", func() {
			generatePacket := func(t protocol.PacketType) []byte {
				return []byte{
					0x80 ^ uint8(t),
					0x1, 0x2, 0x3, 0x4, // version number
					0x55,                                           // connection ID lengths
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // destination connection ID
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // source connection ID
					0xde, 0xca, 0xfb, 0xad, // packet number
				}
			}

			It("parses a long header", func() {
				b := bytes.NewReader(generatePacket(protocol.PacketTypeInitial))
				h, err := parseHeader(b, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.Type).To(Equal(protocol.PacketTypeInitial))
				Expect(h.IsLongHeader).To(BeTrue())
				Expect(h.OmitConnectionID).To(BeFalse())
				Expect(h.DestConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}))
				Expect(h.SrcConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}))
				Expect(h.PacketNumber).To(Equal(protocol.PacketNumber(0xdecafbad)))
				Expect(h.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
				Expect(h.Version).To(Equal(protocol.VersionNumber(0x1020304)))
				Expect(h.IsVersionNegotiation).To(BeFalse())
				Expect(b.Len()).To(BeZero())
			})

			It("rejects packets sent by the client that use packet types for packets sent by the server", func() {
				b := bytes.NewReader(generatePacket(protocol.PacketTypeRetry))
				_, err := parseHeader(b, protocol.PerspectiveClient)
				Expect(err).To(MatchError(fmt.Sprintf("InvalidPacketHeader: Received packet with invalid packet type: %d", protocol.PacketTypeRetry)))
			})

			It("rejects packets sent by the client that use packet types for packets sent by the server", func() {
				b := bytes.NewReader(generatePacket(protocol.PacketType0RTT))
				_, err := parseHeader(b, protocol.PerspectiveServer)
				Expect(err).To(MatchError(fmt.Sprintf("InvalidPacketHeader: Received packet with invalid packet type: %d", protocol.PacketType0RTT)))
			})

			It("rejects packets sent with an unknown packet type", func() {
				b := bytes.NewReader(generatePacket(42))
				_, err := parseHeader(b, protocol.PerspectiveServer)
				Expect(err).To(MatchError("InvalidPacketHeader: Received packet with invalid packet type: 42"))
			})

			It("rejects version 0 for packets sent by the client", func() {
				data := []byte{
					0x80 ^ uint8(protocol.PacketTypeInitial),
					0x0, 0x0, 0x0, 0x0, // version number
					0x55,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // dest connection ID
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // src connection ID
					0xde, 0xca, 0xfb, 0xad, // packet number
				}
				_, err := parseHeader(bytes.NewReader(data), protocol.PerspectiveClient)
				Expect(err).To(MatchError(qerr.InvalidVersion))
			})

			It("errors on EOF", func() {
				data := generatePacket(protocol.PacketTypeInitial)
				for i := 0; i < len(data); i++ {
					_, err := parseHeader(bytes.NewReader(data[:i]), protocol.PerspectiveClient)
					Expect(err).To(Equal(io.EOF))
				}
			})
		})

		Context("short headers", func() {
			It("reads a short header with a connection ID", func() {
				data := []byte{
					0x30,                                           // 1 byte packet number
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0x42, // packet number
				}
				b := bytes.NewReader(data)
				h, err := parseHeader(b, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsLongHeader).To(BeFalse())
				Expect(h.KeyPhase).To(Equal(0))
				Expect(h.OmitConnectionID).To(BeFalse())
				Expect(h.DestConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}))
				Expect(h.SrcConnectionID).To(BeEmpty())
				Expect(h.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
				Expect(h.IsVersionNegotiation).To(BeFalse())
				Expect(b.Len()).To(BeZero())
			})

			It("reads the Key Phase Bit", func() {
				data := []byte{
					0x30 ^ 0x40,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0x11,
				}
				b := bytes.NewReader(data)
				h, err := parseHeader(b, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsLongHeader).To(BeFalse())
				Expect(h.KeyPhase).To(Equal(1))
				Expect(b.Len()).To(BeZero())
			})

			It("reads a header with a 2 byte packet number", func() {
				data := []byte{
					0x30 ^ 0x40 ^ 0x1,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0x13, 0x37, // packet number
				}
				b := bytes.NewReader(data)
				h, err := parseHeader(b, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsLongHeader).To(BeFalse())
				Expect(h.PacketNumber).To(Equal(protocol.PacketNumber(0x1337)))
				Expect(h.PacketNumberLen).To(Equal(protocol.PacketNumberLen2))
				Expect(b.Len()).To(BeZero())
			})

			It("reads a header with a 4 byte packet number", func() {
				data := []byte{
					0x30 ^ 0x40 ^ 0x2,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0xde, 0xad, 0xbe, 0xef, // packet number
				}
				b := bytes.NewReader(data)
				h, err := parseHeader(b, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsLongHeader).To(BeFalse())
				Expect(h.PacketNumber).To(Equal(protocol.PacketNumber(0xdeadbeef)))
				Expect(h.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
				Expect(b.Len()).To(BeZero())
			})

			It("rejects headers that have an invalid type", func() {
				data := []byte{
					0x30 ^ 0x40 ^ 0x3,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0xde, 0xad, 0xbe, 0xef, // packet number
				}
				b := bytes.NewReader(data)
				_, err := parseHeader(b, protocol.PerspectiveClient)
				Expect(err).To(MatchError("invalid short header type"))
			})

			It("rejects headers that have bit 3,4 and 5 set incorrectly", func() {
				data := []byte{
					0x38 ^ 0x2,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0xde, 0xca, 0xfb, 0xad, // packet number
				}
				b := bytes.NewReader(data)
				_, err := parseHeader(b, protocol.PerspectiveClient)
				Expect(err).To(MatchError("invalid bits 3, 4 and 5"))
			})

			It("errors on EOF", func() {
				data := []byte{
					0x30 ^ 0x2,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0xde, 0xca, 0xfb, 0xad, // packet number
				}
				for i := 0; i < len(data); i++ {
					_, err := parseHeader(bytes.NewReader(data[:i]), protocol.PerspectiveClient)
					Expect(err).To(Equal(io.EOF))
				}
			})
		})
	})

	Context("writing", func() {
		var buf *bytes.Buffer

		BeforeEach(func() {
			buf = &bytes.Buffer{}
		})

		Context("long header", func() {
			It("writes", func() {
				err := (&Header{
					IsLongHeader:     true,
					Type:             0x5,
					DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
					SrcConnectionID:  protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
					PacketNumber:     0xdecafbad,
					Version:          0x1020304,
				}).writeHeader(buf)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x80 ^ 0x5,
					0x1, 0x2, 0x3, 0x4, // version number
					0x55,                                           // connection ID lengths
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0xde, 0xca, 0xfb, 0xad, // packet number
				}))
			})

			It("refuses to write headers with unequal destination and source connection IDs", func() {
				err := (&Header{
					IsLongHeader:     true,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					SrcConnectionID:  protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1},
				}).writeHeader(buf)
				Expect(err).To(MatchError("Header: can't write a header with different source and destination connection ID"))
			})
		})

		Context("short header", func() {
			It("writes a header with connection ID", func() {
				err := (&Header{
					DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
					PacketNumberLen:  protocol.PacketNumberLen1,
					PacketNumber:     0x42,
				}).writeHeader(buf)
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
				}).writeHeader(buf)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x30,
					0x42, // packet number
				}))
			})

			It("writes a header with a 2 byte packet number", func() {
				err := (&Header{
					OmitConnectionID: true,
					PacketNumberLen:  protocol.PacketNumberLen2,
					PacketNumber:     0x1337,
				}).writeHeader(buf)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x30 | 0x1,
					0x13, 0x37, // packet number
				}))
			})

			It("writes a header with a 4 byte packet number", func() {
				err := (&Header{
					OmitConnectionID: true,
					PacketNumberLen:  protocol.PacketNumberLen4,
					PacketNumber:     0xdecafbad,
				}).writeHeader(buf)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x30 | 0x2,
					0xde, 0xca, 0xfb, 0xad, // packet number
				}))
			})

			It("errors when given an invalid packet number length", func() {
				err := (&Header{
					OmitConnectionID: true,
					PacketNumberLen:  3,
					PacketNumber:     0xdecafbad,
				}).writeHeader(buf)
				Expect(err).To(MatchError("invalid packet number length: 3"))
			})

			It("writes the Key Phase Bit", func() {
				err := (&Header{
					KeyPhase:         1,
					OmitConnectionID: true,
					PacketNumberLen:  protocol.PacketNumberLen1,
					PacketNumber:     0x42,
				}).writeHeader(buf)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x30 | 0x40,
					0x42, // packet number
				}))
			})
		})
	})

	Context("length", func() {
		var buf *bytes.Buffer

		BeforeEach(func() {
			buf = &bytes.Buffer{}
		})

		It("has the right length for the long header", func() {
			h := &Header{
				IsLongHeader:     true,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* conn ID len */ + 8 /* dest conn id */ + 8 /* src conn id */ + 4 /* packet number */
			Expect(h.getHeaderLength()).To(BeEquivalentTo(expectedLen))
			err := h.writeHeader(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(expectedLen))
		})

		It("has the right length for a short header containing a connection ID", func() {
			h := &Header{
				PacketNumberLen:  protocol.PacketNumberLen1,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			}
			Expect(h.getHeaderLength()).To(Equal(protocol.ByteCount(1 + 8 + 1)))
			err := h.writeHeader(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(10))
		})

		It("has the right length for a short header without a connection ID", func() {
			h := &Header{
				OmitConnectionID: true,
				PacketNumberLen:  protocol.PacketNumberLen1,
			}
			Expect(h.getHeaderLength()).To(Equal(protocol.ByteCount(1 + 1)))
			err := h.writeHeader(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(2))
		})

		It("has the right length for a short header with a 2 byte packet number", func() {
			h := &Header{
				OmitConnectionID: true,
				PacketNumberLen:  protocol.PacketNumberLen2,
			}
			Expect(h.getHeaderLength()).To(Equal(protocol.ByteCount(1 + 2)))
			err := h.writeHeader(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(3))
		})

		It("has the right length for a short header with a 5 byte packet number", func() {
			h := &Header{
				OmitConnectionID: true,
				PacketNumberLen:  protocol.PacketNumberLen4,
			}
			Expect(h.getHeaderLength()).To(Equal(protocol.ByteCount(1 + 4)))
			err := h.writeHeader(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(5))
		})

		It("errors when given an invalid packet number length", func() {
			h := &Header{PacketNumberLen: 5}
			_, err := h.getHeaderLength()
			Expect(err).To(MatchError("invalid packet number length: 5"))
		})
	})

	Context("logging", func() {
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
			hdr, err := parseLongHeader(bytes.NewReader(data[1:]), protocol.PerspectiveServer, data[0])
			Expect(err).ToNot(HaveOccurred())
			hdr.logHeader(logger)
			Expect(buf.String()).To(ContainSubstring("VersionNegotiationPacket{DestConnectionID: 0xdeadbeefcafe1337, SrcConnectionID: 0xdecafbad13371337"))
			Expect(buf.String()).To(ContainSubstring("0x12345678"))
			Expect(buf.String()).To(ContainSubstring("0x87654321"))
		})

		It("logs Long Headers", func() {
			(&Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				PacketNumber:     0x1337,
				DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
				SrcConnectionID:  protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad, 0x013, 0x37, 0x13, 0x37},
				Version:          0xfeed,
			}).logHeader(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Handshake, DestConnectionID: 0xdeadbeefcafe1337, SrcConnectionID: 0xdecafbad13371337, PacketNumber: 0x1337, Version: 0xfeed}"))
		})

		It("logs Short Headers containing a connection ID", func() {
			(&Header{
				KeyPhase:         1,
				PacketNumber:     0x1337,
				PacketNumberLen:  4,
				DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
			}).logHeader(logger)
			Expect(buf.String()).To(ContainSubstring("Short Header{DestConnectionID: 0xdeadbeefcafe1337, PacketNumber: 0x1337, PacketNumberLen: 4, KeyPhase: 1}"))
		})
	})
})
