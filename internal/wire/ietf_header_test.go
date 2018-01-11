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

var _ = Describe("IETF draft Header", func() {
	Context("parsing", func() {
		Context("Version Negotiation Packets", func() {
			It("parses", func() {
				versions := []protocol.VersionNumber{0x22334455, 0x33445566}
				data := ComposeVersionNegotiation(0x1234567890, 0x1337, versions)
				b := bytes.NewReader(data)
				h, err := parseHeader(b, protocol.PerspectiveServer)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsVersionNegotiation).To(BeTrue())
				Expect(h.Version).To(BeZero())
				Expect(h.ConnectionID).To(Equal(protocol.ConnectionID(0x1234567890)))
				Expect(h.PacketNumber).To(Equal(protocol.PacketNumber(0x1337)))
				for _, v := range versions {
					Expect(h.SupportedVersions).To(ContainElement(v))
				}
			})

			It("errors if it contains versions of the wrong length", func() {
				versions := []protocol.VersionNumber{0x22334455, 0x33445566}
				data := ComposeVersionNegotiation(0x1234567890, 0x1337, versions)
				b := bytes.NewReader(data[:len(data)-2])
				_, err := parseHeader(b, protocol.PerspectiveServer)
				Expect(err).To(MatchError(qerr.InvalidVersionNegotiationPacket))
			})

			It("errors if the version list is emtpy", func() {
				versions := []protocol.VersionNumber{0x22334455}
				data := ComposeVersionNegotiation(0x1234567890, 0x1337, versions)
				// remove 8 bytes (two versions), since ComposeVersionNegotiation also added a reserved version number
				_, err := parseHeader(bytes.NewReader(data[:len(data)-8]), protocol.PerspectiveServer)
				Expect(err).To(MatchError("InvalidVersionNegotiationPacket: empty version list"))
			})
		})

		Context("long headers", func() {
			generatePacket := func(t protocol.PacketType) []byte {
				return []byte{
					0x80 ^ uint8(t),
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0x1, 0x2, 0x3, 0x4, // version number
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
				Expect(h.ConnectionID).To(Equal(protocol.ConnectionID(0xdeadbeefcafe1337)))
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
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0x0, 0x0, 0x0, 0x0, // version number
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
					0x40 ^ 0x1,                                     //
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0x42, // packet number
				}
				b := bytes.NewReader(data)
				h, err := parseHeader(b, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsLongHeader).To(BeFalse())
				Expect(h.KeyPhase).To(Equal(0))
				Expect(h.OmitConnectionID).To(BeFalse())
				Expect(h.ConnectionID).To(Equal(protocol.ConnectionID(0xdeadbeefcafe1337)))
				Expect(h.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
				Expect(h.IsVersionNegotiation).To(BeFalse())
				Expect(b.Len()).To(BeZero())
			})

			It("reads the Key Phase Bit", func() {
				data := []byte{
					0x20 ^ 0x1,
					0x11,
				}
				b := bytes.NewReader(data)
				h, err := parseHeader(b, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsLongHeader).To(BeFalse())
				Expect(h.KeyPhase).To(Equal(1))
				Expect(b.Len()).To(BeZero())
			})

			It("reads a header with ommited connection ID", func() {
				data := []byte{
					0x1,
					0x21, // packet number
				}
				b := bytes.NewReader(data)
				h, err := parseHeader(b, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsLongHeader).To(BeFalse())
				Expect(h.OmitConnectionID).To(BeTrue())
				Expect(h.PacketNumber).To(Equal(protocol.PacketNumber(0x21)))
				Expect(h.PacketNumberLen).To(Equal(protocol.PacketNumberLen1))
				Expect(b.Len()).To(BeZero())
			})

			It("reads a header with a 2 byte packet number", func() {
				data := []byte{
					0x2,
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
					0x3,
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

			It("errors on EOF", func() {
				data := []byte{
					0x40 ^ 0x3,
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
					IsLongHeader: true,
					Type:         0x5,
					ConnectionID: 0xdeadbeefcafe1337,
					PacketNumber: 0xdecafbad,
					Version:      0x1020304,
				}).writeHeader(buf)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x80 ^ 0x5,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0x1, 0x2, 0x3, 0x4, // version number
					0xde, 0xca, 0xfb, 0xad, // packet number
				}))
			})
		})

		Context("short header", func() {
			It("writes a header with connection ID", func() {
				err := (&Header{
					ConnectionID:    0xdeadbeefcafe1337,
					PacketNumberLen: protocol.PacketNumberLen1,
					PacketNumber:    0x42,
				}).writeHeader(buf)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x40 ^ 0x1,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0x42, // packet number
				}))
			})

			It("writes a header without connection ID", func() {
				err := (&Header{
					OmitConnectionID: true,
					PacketNumberLen:  protocol.PacketNumberLen1,
					PacketNumber:     0x42,
				}).writeHeader(buf)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x1,
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
					0x2,
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
					0x3,
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
					0x20 ^ 0x1,
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
			h := &Header{IsLongHeader: true}
			Expect(h.getHeaderLength()).To(Equal(protocol.ByteCount(17)))
			err := h.writeHeader(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(17))
		})

		It("has the right length for a short header containing a connection ID", func() {
			h := &Header{
				PacketNumberLen: protocol.PacketNumberLen1,
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
		var buf bytes.Buffer

		BeforeEach(func() {
			buf.Reset()
			utils.SetLogLevel(utils.LogLevelDebug)
			log.SetOutput(&buf)
		})

		AfterEach(func() {
			utils.SetLogLevel(utils.LogLevelNothing)
			log.SetOutput(os.Stdout)
		})

		It("logs Long Headers", func() {
			(&Header{
				IsLongHeader: true,
				Type:         protocol.PacketTypeHandshake,
				PacketNumber: 0x1337,
				ConnectionID: 0xdeadbeef,
				Version:      253,
			}).logHeader()
			Expect(string(buf.Bytes())).To(ContainSubstring("Long Header{Type: Handshake, ConnectionID: 0xdeadbeef, PacketNumber: 0x1337, Version: 253}"))
		})

		It("logs Short Headers containing a connection ID", func() {
			(&Header{
				KeyPhase:        1,
				PacketNumber:    0x1337,
				PacketNumberLen: 4,
				ConnectionID:    0xdeadbeef,
			}).logHeader()
			Expect(string(buf.Bytes())).To(ContainSubstring("Short Header{ConnectionID: 0xdeadbeef, PacketNumber: 0x1337, PacketNumberLen: 4, KeyPhase: 1}"))
		})

		It("logs Short Headers with omitted connection ID", func() {
			(&Header{
				PacketNumber:     0x12,
				PacketNumberLen:  1,
				OmitConnectionID: true,
			}).logHeader()
			Expect(string(buf.Bytes())).To(ContainSubstring("Short Header{ConnectionID: (omitted), PacketNumber: 0x12, PacketNumberLen: 1, KeyPhase: 0}"))
		})
	})
})
