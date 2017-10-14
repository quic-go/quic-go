package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Header", func() {
	Context("parsing", func() {
		Context("long headers", func() {
			var data []byte

			BeforeEach(func() {
				data = []byte{
					0x80 ^ 0x3,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0xde, 0xca, 0xfb, 0xad, // packet number
					0x1, 0x2, 0x3, 0x4, // version number
				}
			})

			It("parses a long header", func() {
				b := bytes.NewReader(data)
				h, err := ParseHeader(b, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.Type).To(BeEquivalentTo(3))
				Expect(h.IsLongHeader).To(BeTrue())
				Expect(h.OmitConnectionID).To(BeFalse())
				Expect(h.ConnectionID).To(Equal(protocol.ConnectionID(0xdeadbeefcafe1337)))
				Expect(h.PacketNumber).To(Equal(protocol.PacketNumber(0xdecafbad)))
				Expect(h.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
				Expect(h.Version).To(Equal(protocol.VersionNumber(0x1020304)))
				Expect(b.Len()).To(BeZero())
			})

			It("errors on EOF", func() {
				for i := 0; i < len(data); i++ {
					_, err := ParseHeader(bytes.NewReader(data[:i]), protocol.PerspectiveClient)
					Expect(err).To(Equal(io.EOF))
				}
			})

			Context("Version Negotiation Packets", func() {
				BeforeEach(func() {
					data[0] = 0x80 ^ 0x1 // set the type byte to Version Negotiation Packet
				})

				It("parses", func() {
					data = append(data, []byte{
						0x22, 0x33, 0x44, 0x55,
						0x33, 0x44, 0x55, 0x66}...,
					)
					b := bytes.NewReader(data)
					h, err := ParseHeader(b, protocol.PerspectiveServer)
					Expect(err).ToNot(HaveOccurred())
					Expect(h.SupportedVersions).To(Equal([]protocol.VersionNumber{
						0x22334455,
						0x33445566,
					}))
				})

				It("errors if it contains versions of the wrong length", func() {
					data = append(data, []byte{0x22, 0x33}...) // too short. Should be 4 bytes.
					b := bytes.NewReader(data)
					_, err := ParseHeader(b, protocol.PerspectiveServer)
					Expect(err).To(MatchError(qerr.InvalidVersionNegotiationPacket))
				})

				It("errors if it was sent by the client", func() {
					data = append(data, []byte{0x22, 0x33, 0x44, 0x55}...)
					b := bytes.NewReader(data)
					_, err := ParseHeader(b, protocol.PerspectiveClient)
					Expect(err).To(MatchError("InvalidVersionNegotiationPacket: sent by the client"))
				})
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
				h, err := ParseHeader(b, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsLongHeader).To(BeFalse())
				Expect(h.KeyPhase).To(Equal(0))
				Expect(h.OmitConnectionID).To(BeFalse())
				Expect(h.ConnectionID).To(Equal(protocol.ConnectionID(0xdeadbeefcafe1337)))
				Expect(h.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
				Expect(b.Len()).To(BeZero())
			})

			It("reads the Key Phase Bit", func() {
				data := []byte{
					0x20 ^ 0x1,
					0x11,
				}
				b := bytes.NewReader(data)
				h, err := ParseHeader(b, protocol.PerspectiveClient)
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
				h, err := ParseHeader(b, protocol.PerspectiveClient)
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
				h, err := ParseHeader(b, protocol.PerspectiveClient)
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
				h, err := ParseHeader(b, protocol.PerspectiveClient)
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
					_, err := ParseHeader(bytes.NewReader(data[:i]), protocol.PerspectiveClient)
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
				}).Write(buf)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x80 ^ 0x5,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0xde, 0xca, 0xfb, 0xad, // packet number
					0x1, 0x2, 0x3, 0x4, // version number
				}))
			})
		})

		Context("short header", func() {
			It("writes a header with connection ID", func() {
				err := (&Header{
					ConnectionID:    0xdeadbeefcafe1337,
					PacketNumberLen: protocol.PacketNumberLen1,
					PacketNumber:    0x42,
				}).Write(buf)
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
				}).Write(buf)
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
				}).Write(buf)
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
				}).Write(buf)
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
				}).Write(buf)
				Expect(err).To(MatchError("invalid packet number length: 3"))
			})

			It("writes the Key Phase Bit", func() {
				err := (&Header{
					KeyPhase:         1,
					OmitConnectionID: true,
					PacketNumberLen:  protocol.PacketNumberLen1,
					PacketNumber:     0x42,
				}).Write(buf)
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
			Expect(h.GetLength()).To(Equal(protocol.ByteCount(17)))
			err := h.Write(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(17))
		})

		It("has the right length for a short header containing a connection ID", func() {
			h := &Header{
				PacketNumberLen: protocol.PacketNumberLen1,
			}
			Expect(h.GetLength()).To(Equal(protocol.ByteCount(1 + 8 + 1)))
			err := h.Write(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(10))
		})

		It("has the right length for a short header without a connection ID", func() {
			h := &Header{
				OmitConnectionID: true,
				PacketNumberLen:  protocol.PacketNumberLen1,
			}
			Expect(h.GetLength()).To(Equal(protocol.ByteCount(1 + 1)))
			err := h.Write(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(2))
		})

		It("has the right length for a short header with a 2 byte packet number", func() {
			h := &Header{
				OmitConnectionID: true,
				PacketNumberLen:  protocol.PacketNumberLen2,
			}
			Expect(h.GetLength()).To(Equal(protocol.ByteCount(1 + 2)))
			err := h.Write(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(3))
		})

		It("has the right length for a short header with a 5 byte packet number", func() {
			h := &Header{
				OmitConnectionID: true,
				PacketNumberLen:  protocol.PacketNumberLen4,
			}
			Expect(h.GetLength()).To(Equal(protocol.ByteCount(1 + 4)))
			err := h.Write(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(5))
		})

		It("errors when given an invalid packet number length", func() {
			h := &Header{PacketNumberLen: 5}
			_, err := h.GetLength()
			Expect(err).To(MatchError("invalid packet number length: 5"))
		})
	})
})
