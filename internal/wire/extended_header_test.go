package wire

import (
	"bytes"
	"log"
	"os"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Header", func() {
	Context("Writing", func() {
		Context("Long Header, version 1", func() {
			srcConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})

			It("writes", func() {
				b, err := (&ExtendedHeader{
					Header: Header{
						Type:             protocol.PacketTypeHandshake,
						DestConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}),
						SrcConnectionID:  protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad, 0x0, 0x0, 0x13, 0x37}),
						Version:          0x1020304,
						Length:           protocol.InitialPacketSizeIPv4,
					},
					PacketNumber:    0xdecaf,
					PacketNumberLen: protocol.PacketNumberLen3,
				}).Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				expected := []byte{
					0xc0 | 0x2<<4 | 0x2,
					0x1, 0x2, 0x3, 0x4, // version number
					0x6,                                // dest connection ID length
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // dest connection ID
					0x8,                                          // src connection ID length
					0xde, 0xca, 0xfb, 0xad, 0x0, 0x0, 0x13, 0x37, // source connection ID
				}
				expected = append(expected, encodeVarInt(protocol.InitialPacketSizeIPv4)...) // length
				expected = append(expected, []byte{0xd, 0xec, 0xaf}...)                      // packet number
				Expect(b).To(Equal(expected))
			})

			It("writes a header with a 20 byte connection ID", func() {
				b, err := (&ExtendedHeader{
					Header: Header{
						SrcConnectionID:  srcConnID,
						DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}), // connection IDs must be at most 20 bytes long
						Version:          0x1020304,
						Type:             0x5,
					},
					PacketNumber:    0xdecafbad,
					PacketNumberLen: protocol.PacketNumberLen4,
				}).Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(b).To(ContainSubstring(string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})))
			})

			It("writes an Initial containing a token", func() {
				token := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
				b, err := (&ExtendedHeader{
					Header: Header{
						Version: 0x1020304,
						Type:    protocol.PacketTypeInitial,
						Token:   token,
					},
					PacketNumber:    0xdecafbad,
					PacketNumberLen: protocol.PacketNumberLen4,
				}).Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(b[0]>>4&0b11 == 0)
				expectedSubstring := append(encodeVarInt(uint64(len(token))), token...)
				Expect(b).To(ContainSubstring(string(expectedSubstring)))
			})

			It("uses a 2-byte encoding for the length on Initial packets", func() {
				b, err := (&ExtendedHeader{
					Header: Header{
						Version: 0x1020304,
						Type:    protocol.PacketTypeInitial,
						Length:  37,
					},
					PacketNumber:    0xdecafbad,
					PacketNumberLen: protocol.PacketNumberLen4,
				}).Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				lengthEncoded := quicvarint.AppendWithLen(nil, 37, 2)
				Expect(b[len(b)-6 : len(b)-4]).To(Equal(lengthEncoded))
			})

			It("writes a Retry packet", func() {
				token := []byte("Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.")
				b, err := (&ExtendedHeader{Header: Header{
					Version: protocol.Version1,
					Type:    protocol.PacketTypeRetry,
					Token:   token,
				}}).Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				expected := []byte{0xc0 | 0b11<<4}
				expected = appendVersion(expected, protocol.Version1)
				expected = append(expected, 0x0) // dest connection ID length
				expected = append(expected, 0x0) // src connection ID length
				expected = append(expected, token...)
				Expect(b).To(Equal(expected))
			})
		})

		Context("long header, version 2", func() {
			It("writes an Initial", func() {
				b, err := (&ExtendedHeader{
					Header: Header{
						Version: protocol.Version2,
						Type:    protocol.PacketTypeInitial,
					},
					PacketNumber:    0xdecafbad,
					PacketNumberLen: protocol.PacketNumberLen4,
				}).Append(nil, protocol.Version2)
				Expect(err).ToNot(HaveOccurred())
				Expect(b[0]>>4&0b11 == 0b01)
			})

			It("writes a Retry packet", func() {
				token := []byte("Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.")
				b, err := (&ExtendedHeader{Header: Header{
					Version: protocol.Version2,
					Type:    protocol.PacketTypeRetry,
					Token:   token,
				}}).Append(nil, protocol.Version2)
				Expect(err).ToNot(HaveOccurred())
				expected := []byte{0xc0 | 0b00<<4}
				expected = appendVersion(expected, protocol.Version2)
				expected = append(expected, 0x0) // dest connection ID length
				expected = append(expected, 0x0) // src connection ID length
				expected = append(expected, token...)
				Expect(b).To(Equal(expected))
			})

			It("writes a Handshake Packet", func() {
				b, err := (&ExtendedHeader{
					Header: Header{
						Version: protocol.Version2,
						Type:    protocol.PacketTypeHandshake,
					},
					PacketNumber:    0xdecafbad,
					PacketNumberLen: protocol.PacketNumberLen4,
				}).Append(nil, protocol.Version2)
				Expect(err).ToNot(HaveOccurred())
				Expect(b[0]>>4&0b11 == 0b11)
			})

			It("writes a 0-RTT Packet", func() {
				b, err := (&ExtendedHeader{
					Header: Header{
						Version: protocol.Version2,
						Type:    protocol.PacketType0RTT,
					},
					PacketNumber:    0xdecafbad,
					PacketNumberLen: protocol.PacketNumberLen4,
				}).Append(nil, protocol.Version2)
				Expect(err).ToNot(HaveOccurred())
				Expect(b[0]>>4&0b11 == 0b10)
			})
		})
	})

	Context("getting the length", func() {
		It("has the right length for the Long Header, for a short length", func() {
			h := &ExtendedHeader{
				Header: Header{
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					SrcConnectionID:  protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					Length:           1,
				},
				PacketNumberLen: protocol.PacketNumberLen1,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* dest conn ID len */ + 8 /* dest conn id */ + 1 /* src conn ID len */ + 8 /* src conn id */ + 2 /* length */ + 1 /* packet number */
			Expect(h.GetLength(protocol.Version1)).To(BeEquivalentTo(expectedLen))
			b, err := h.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(HaveLen(expectedLen))
		})

		It("has the right length for the Long Header, for a long length", func() {
			h := &ExtendedHeader{
				Header: Header{
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					SrcConnectionID:  protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					Length:           1500,
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* dest conn id len */ + 8 /* dest conn id */ + 1 /* src conn ID len */ + 8 /* src conn id */ + 2 /* long len */ + 2 /* packet number */
			Expect(h.GetLength(protocol.Version1)).To(BeEquivalentTo(expectedLen))
			b, err := h.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(HaveLen(expectedLen))
		})

		It("has the right length for an Initial that has a short length", func() {
			h := &ExtendedHeader{
				Header: Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					SrcConnectionID:  protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
					Length:           15,
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* dest conn id len */ + 8 /* dest conn id */ + 1 /* src conn ID len */ + 4 /* src conn id */ + 1 /* token length */ + 2 /* length len */ + 2 /* packet number */
			Expect(h.GetLength(protocol.Version1)).To(BeEquivalentTo(expectedLen))
			b, err := h.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(HaveLen(expectedLen))
		})

		It("has the right length for an Initial not containing a Token", func() {
			h := &ExtendedHeader{
				Header: Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					SrcConnectionID:  protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
					Length:           1500,
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* dest conn id len */ + 8 /* dest conn id */ + 1 /* src conn ID len */ + 4 /* src conn id */ + 1 /* token length */ + 2 /* length len */ + 2 /* packet number */
			Expect(h.GetLength(protocol.Version1)).To(BeEquivalentTo(expectedLen))
			b, err := h.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(HaveLen(expectedLen))
		})

		It("has the right length for an Initial containing a Token", func() {
			h := &ExtendedHeader{
				Header: Header{
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					SrcConnectionID:  protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
					Type:             protocol.PacketTypeInitial,
					Length:           1500,
					Token:            []byte("foo"),
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* dest conn id len */ + 8 /* dest conn id */ + 1 /* src conn id len */ + 4 /* src conn id */ + 1 /* token length */ + 3 /* token */ + 2 /* long len */ + 2 /* packet number */
			Expect(h.GetLength(protocol.Version1)).To(BeEquivalentTo(expectedLen))
			b, err := h.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(HaveLen(expectedLen))
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

		It("logs Long Headers", func() {
			(&ExtendedHeader{
				Header: Header{
					DestConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}),
					SrcConnectionID:  protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad, 0x013, 0x37, 0x13, 0x37}),
					Type:             protocol.PacketTypeHandshake,
					Length:           54321,
					Version:          0xfeed,
				},
				PacketNumber:    1337,
				PacketNumberLen: protocol.PacketNumberLen2,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Handshake, DestConnectionID: deadbeefcafe1337, SrcConnectionID: decafbad13371337, PacketNumber: 1337, PacketNumberLen: 2, Length: 54321, Version: 0xfeed}"))
		})

		It("logs Initial Packets with a Token", func() {
			(&ExtendedHeader{
				Header: Header{
					DestConnectionID: protocol.ParseConnectionID([]byte{0xca, 0xfe, 0x13, 0x37}),
					SrcConnectionID:  protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
					Type:             protocol.PacketTypeInitial,
					Token:            []byte{0xde, 0xad, 0xbe, 0xef},
					Length:           100,
					Version:          0xfeed,
				},
				PacketNumber:    42,
				PacketNumberLen: protocol.PacketNumberLen2,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Initial, DestConnectionID: cafe1337, SrcConnectionID: decafbad, Token: 0xdeadbeef, PacketNumber: 42, PacketNumberLen: 2, Length: 100, Version: 0xfeed}"))
		})

		It("logs Initial packets without a Token", func() {
			(&ExtendedHeader{
				Header: Header{
					DestConnectionID: protocol.ParseConnectionID([]byte{0xca, 0xfe, 0x13, 0x37}),
					SrcConnectionID:  protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
					Type:             protocol.PacketTypeInitial,
					Length:           100,
					Version:          0xfeed,
				},
				PacketNumber:    42,
				PacketNumberLen: protocol.PacketNumberLen2,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Initial, DestConnectionID: cafe1337, SrcConnectionID: decafbad, Token: (empty), PacketNumber: 42, PacketNumberLen: 2, Length: 100, Version: 0xfeed}"))
		})

		It("logs Retry packets with a Token", func() {
			(&ExtendedHeader{
				Header: Header{
					DestConnectionID: protocol.ParseConnectionID([]byte{0xca, 0xfe, 0x13, 0x37}),
					SrcConnectionID:  protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
					Type:             protocol.PacketTypeRetry,
					Token:            []byte{0x12, 0x34, 0x56},
					Version:          0xfeed,
				},
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Retry, DestConnectionID: cafe1337, SrcConnectionID: decafbad, Token: 0x123456, Version: 0xfeed}"))
		})
	})
})
