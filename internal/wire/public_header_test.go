package wire

import (
	"bytes"
	"encoding/binary"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Public Header", func() {
	Context("parsing the connection ID", func() {
		It("does not accept truncated connection ID as a server", func() {
			b := bytes.NewReader([]byte{0x00, 0x01})
			_, err := PeekConnectionID(b, protocol.PerspectiveClient)
			Expect(err).To(MatchError(errReceivedTruncatedConnectionID))
		})

		It("gets the connection ID", func() {
			b := bytes.NewReader([]byte{0x09, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x51, 0x30, 0x33, 0x34, 0x01})
			len := b.Len()
			connID, err := PeekConnectionID(b, protocol.PerspectiveClient)
			Expect(err).ToNot(HaveOccurred())
			Expect(connID).To(Equal(protocol.ConnectionID(0x4cfa9f9b668619f6)))
			Expect(b.Len()).To(Equal(len))
		})

		It("errors if the Public Header is too short", func() {
			b := bytes.NewReader([]byte{0x09, 0xf6, 0x19, 0x86, 0x66, 0x9b})
			_, err := PeekConnectionID(b, protocol.PerspectiveClient)
			Expect(err).To(HaveOccurred())
		})

		It("errors if the Public Header is empty", func() {
			b := bytes.NewReader([]byte{})
			_, err := PeekConnectionID(b, protocol.PerspectiveClient)
			Expect(err).To(HaveOccurred())
		})

		It("accepts a truncated connection ID as a client", func() {
			b := bytes.NewReader([]byte{0x00, 0x01})
			len := b.Len()
			connID, err := PeekConnectionID(b, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			Expect(connID).To(BeZero())
			Expect(b.Len()).To(Equal(len))
		})
	})

	Context("when parsing", func() {
		It("accepts a sample client header", func() {
			b := bytes.NewReader([]byte{0x09, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x51, 0x30, 0x33, 0x34, 0x01})
			hdr, err := ParsePublicHeader(b, protocol.PerspectiveClient, protocol.VersionUnknown)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.VersionFlag).To(BeTrue())
			Expect(hdr.ResetFlag).To(BeFalse())
			Expect(hdr.ConnectionID).To(Equal(protocol.ConnectionID(0x4cfa9f9b668619f6)))
			Expect(hdr.VersionNumber).To(Equal(protocol.VersionNumber(34)))
			Expect(hdr.SupportedVersions).To(BeEmpty())
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(b.Len()).To(BeZero())
		})

		It("does not accept truncated connection ID as a server", func() {
			b := bytes.NewReader([]byte{0x00, 0x01})
			_, err := ParsePublicHeader(b, protocol.PerspectiveClient, protocol.VersionWhatever)
			Expect(err).To(MatchError(errReceivedTruncatedConnectionID))
		})

		It("accepts a truncated connection ID as a client", func() {
			b := bytes.NewReader([]byte{0x00, 0x01})
			hdr, err := ParsePublicHeader(b, protocol.PerspectiveServer, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.TruncateConnectionID).To(BeTrue())
			Expect(hdr.ConnectionID).To(BeZero())
			Expect(b.Len()).To(BeZero())
		})

		It("rejects 0 as a connection ID", func() {
			b := bytes.NewReader([]byte{0x09, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x51, 0x30, 0x33, 0x30, 0x01})
			_, err := ParsePublicHeader(b, protocol.PerspectiveClient, protocol.VersionUnknown)
			Expect(err).To(MatchError(errInvalidConnectionID))
		})

		It("reads a PublicReset packet", func() {
			b := bytes.NewReader([]byte{0xa, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8})
			hdr, err := ParsePublicHeader(b, protocol.PerspectiveServer, protocol.VersionUnknown)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.ResetFlag).To(BeTrue())
			Expect(hdr.ConnectionID).ToNot(BeZero())
		})

		It("parses a public reset packet", func() {
			b := bytes.NewReader([]byte{0xa, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
			hdr, err := ParsePublicHeader(b, protocol.PerspectiveServer, protocol.VersionUnknown)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.ResetFlag).To(BeTrue())
			Expect(hdr.VersionFlag).To(BeFalse())
			Expect(hdr.ConnectionID).To(Equal(protocol.ConnectionID(0x0807060504030201)))
		})

		It("reads a diversification nonce sent by the server", func() {
			divNonce := []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
			Expect(divNonce).To(HaveLen(32))
			b := bytes.NewReader(append(append([]byte{0x0c, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c}, divNonce...), 0x37))
			hdr, err := ParsePublicHeader(b, protocol.PerspectiveServer, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.ConnectionID).To(Not(BeZero()))
			Expect(hdr.DiversificationNonce).To(Equal(divNonce))
			Expect(b.Len()).To(BeZero())
		})

		It("returns an unknown version error when receiving a packet without a version for which the version is not given", func() {
			b := bytes.NewReader([]byte{0x10, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0xef})
			_, err := ParsePublicHeader(b, protocol.PerspectiveServer, protocol.VersionUnknown)
			Expect(err).To(MatchError(ErrPacketWithUnknownVersion))
		})

		PIt("rejects diversification nonces sent by the client", func() {
			b := bytes.NewReader([]byte{0x0c, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c,
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
				0x01,
			})
			_, err := ParsePublicHeader(b, protocol.PerspectiveClient, protocol.VersionWhatever)
			Expect(err).To(MatchError("diversification nonces should only be sent by servers"))
		})

		Context("version negotiation packets", func() {
			appendVersion := func(data []byte, v protocol.VersionNumber) []byte {
				data = append(data, []byte{0, 0, 0, 0}...)
				binary.LittleEndian.PutUint32(data[len(data)-4:], protocol.VersionNumberToTag(v))
				return data
			}

			It("parses version negotiation packets sent by the server", func() {
				b := bytes.NewReader(ComposeVersionNegotiation(0x1337, protocol.SupportedVersions))
				hdr, err := ParsePublicHeader(b, protocol.PerspectiveServer, protocol.VersionUnknown)
				Expect(err).ToNot(HaveOccurred())
				Expect(hdr.VersionFlag).To(BeTrue())
				Expect(hdr.VersionNumber).To(BeZero()) // unitialized
				Expect(hdr.SupportedVersions).To(Equal(protocol.SupportedVersions))
				Expect(b.Len()).To(BeZero())
			})

			It("parses a version negotiation packet that contains 0 versions", func() {
				b := bytes.NewReader([]byte{0x9, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c})
				hdr, err := ParsePublicHeader(b, protocol.PerspectiveServer, protocol.VersionUnknown)
				Expect(err).ToNot(HaveOccurred())
				Expect(hdr.VersionFlag).To(BeTrue())
				Expect(hdr.VersionNumber).To(BeZero()) // unitialized
				Expect(hdr.SupportedVersions).To(BeEmpty())
				Expect(b.Len()).To(BeZero())
			})

			It("reads version negotiation packets containing unsupported versions", func() {
				data := []byte{0x9, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c}
				data = appendVersion(data, 1) // unsupported version
				data = appendVersion(data, protocol.SupportedVersions[0])
				data = appendVersion(data, 99) // unsupported version
				b := bytes.NewReader(data)
				hdr, err := ParsePublicHeader(b, protocol.PerspectiveServer, protocol.VersionUnknown)
				Expect(err).ToNot(HaveOccurred())
				Expect(hdr.VersionFlag).To(BeTrue())
				Expect(hdr.SupportedVersions).To(Equal([]protocol.VersionNumber{1, protocol.SupportedVersions[0], 99}))
				Expect(b.Len()).To(BeZero())
			})

			It("errors on invalid version tags", func() {
				data := ComposeVersionNegotiation(0x1337, protocol.SupportedVersions)
				data = append(data, []byte{0x13, 0x37}...)
				b := bytes.NewReader(data)
				_, err := ParsePublicHeader(b, protocol.PerspectiveServer, protocol.VersionUnknown)
				Expect(err).To(MatchError(qerr.InvalidVersionNegotiationPacket))
			})
		})

		Context("Packet Number lengths", func() {
			Context("in little endian encoding", func() {
				version := protocol.Version37

				BeforeEach(func() {
					Expect(utils.GetByteOrder(version)).To(Equal(utils.LittleEndian))
				})

				It("accepts 1-byte packet numbers", func() {
					b := bytes.NewReader([]byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xde})
					hdr, err := ParsePublicHeader(b, protocol.PerspectiveClient, version)
					Expect(err).ToNot(HaveOccurred())
					Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0xde)))
					Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen1))
					Expect(b.Len()).To(BeZero())
				})

				It("accepts 2-byte packet numbers", func() {
					b := bytes.NewReader([]byte{0x18, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xde, 0xca})
					hdr, err := ParsePublicHeader(b, protocol.PerspectiveClient, version)
					Expect(err).ToNot(HaveOccurred())
					Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0xcade)))
					Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen2))
					Expect(b.Len()).To(BeZero())
				})

				It("accepts 4-byte packet numbers", func() {
					b := bytes.NewReader([]byte{0x28, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xad, 0xfb, 0xca, 0xde})
					hdr, err := ParsePublicHeader(b, protocol.PerspectiveClient, version)
					Expect(err).ToNot(HaveOccurred())
					Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0xdecafbad)))
					Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
					Expect(b.Len()).To(BeZero())
				})

				It("accepts 6-byte packet numbers", func() {
					b := bytes.NewReader([]byte{0x38, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x23, 0x42, 0xad, 0xfb, 0xca, 0xde})
					hdr, err := ParsePublicHeader(b, protocol.PerspectiveClient, version)
					Expect(err).ToNot(HaveOccurred())
					Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0xdecafbad4223)))
					Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen6))
					Expect(b.Len()).To(BeZero())
				})
			})

			Context("in big endian encoding", func() {
				version := protocol.Version39

				BeforeEach(func() {
					Expect(utils.GetByteOrder(version)).To(Equal(utils.BigEndian))
				})

				It("accepts 1-byte packet numbers", func() {
					b := bytes.NewReader([]byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xde})
					hdr, err := ParsePublicHeader(b, protocol.PerspectiveClient, version)
					Expect(err).ToNot(HaveOccurred())
					Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0xde)))
					Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen1))
					Expect(b.Len()).To(BeZero())
				})

				It("accepts 2-byte packet numbers", func() {
					b := bytes.NewReader([]byte{0x18, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xde, 0xca})
					hdr, err := ParsePublicHeader(b, protocol.PerspectiveClient, version)
					Expect(err).ToNot(HaveOccurred())
					Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0xdeca)))
					Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen2))
					Expect(b.Len()).To(BeZero())
				})

				It("accepts 4-byte packet numbers", func() {
					b := bytes.NewReader([]byte{0x28, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xad, 0xfb, 0xca, 0xde})
					hdr, err := ParsePublicHeader(b, protocol.PerspectiveClient, version)
					Expect(err).ToNot(HaveOccurred())
					Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0xadfbcade)))
					Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
					Expect(b.Len()).To(BeZero())
				})

				It("accepts 6-byte packet numbers", func() {
					b := bytes.NewReader([]byte{0x38, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x23, 0x42, 0xad, 0xfb, 0xca, 0xde})
					hdr, err := ParsePublicHeader(b, protocol.PerspectiveClient, version)
					Expect(err).ToNot(HaveOccurred())
					Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x2342adfbcade)))
					Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen6))
					Expect(b.Len()).To(BeZero())
				})
			})
		})
	})

	Context("when writing", func() {
		It("writes a sample header as a server", func() {
			b := &bytes.Buffer{}
			hdr := PublicHeader{
				ConnectionID:    0x4cfa9f9b668619f6,
				PacketNumber:    2,
				PacketNumberLen: protocol.PacketNumberLen6,
			}
			err := hdr.Write(b, versionLittleEndian, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()).To(Equal([]byte{0x38, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 2, 0, 0, 0, 0, 0}))
		})

		It("writes a sample header as a client", func() {
			b := &bytes.Buffer{}
			hdr := PublicHeader{
				ConnectionID:    0x4cfa9f9b668619f6,
				PacketNumber:    0x1337,
				PacketNumberLen: protocol.PacketNumberLen6,
			}
			err := hdr.Write(b, versionLittleEndian, protocol.PerspectiveClient)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()).To(Equal([]byte{0x38, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x37, 0x13, 0, 0, 0, 0}))
		})

		It("refuses to write a Public Header if the PacketNumberLen is not set", func() {
			hdr := PublicHeader{
				ConnectionID: 1,
				PacketNumber: 2,
			}
			b := &bytes.Buffer{}
			err := hdr.Write(b, protocol.VersionWhatever, protocol.PerspectiveServer)
			Expect(err).To(MatchError("PublicHeader: PacketNumberLen not set"))
		})

		It("truncates the connection ID", func() {
			b := &bytes.Buffer{}
			hdr := PublicHeader{
				ConnectionID:         0x4cfa9f9b668619f6,
				TruncateConnectionID: true,
				PacketNumberLen:      protocol.PacketNumberLen6,
				PacketNumber:         1,
			}
			err := hdr.Write(b, protocol.VersionWhatever, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()).To(Equal([]byte{0x30, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0}))
		})

		It("writes diversification nonces", func() {
			b := &bytes.Buffer{}
			hdr := PublicHeader{
				ConnectionID:         0x4cfa9f9b668619f6,
				PacketNumber:         1,
				PacketNumberLen:      protocol.PacketNumberLen1,
				DiversificationNonce: bytes.Repeat([]byte{1}, 32),
			}
			err := hdr.Write(b, versionLittleEndian, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()).To(Equal([]byte{
				0x0c, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c,
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
				0x01,
			}))
		})

		It("throws an error if both Reset Flag and Version Flag are set", func() {
			b := &bytes.Buffer{}
			hdr := PublicHeader{
				VersionFlag: true,
				ResetFlag:   true,
			}
			err := hdr.Write(b, protocol.VersionWhatever, protocol.PerspectiveServer)
			Expect(err).To(MatchError(errResetAndVersionFlagSet))
		})

		Context("Version Negotiation packets", func() {
			It("sets the Version Flag for packets sent as a server", func() {
				b := &bytes.Buffer{}
				hdr := PublicHeader{
					VersionFlag:     true,
					ConnectionID:    0x4cfa9f9b668619f6,
					PacketNumber:    2,
					PacketNumberLen: protocol.PacketNumberLen6,
				}
				err := hdr.Write(b, protocol.VersionWhatever, protocol.PerspectiveServer)
				Expect(err).ToNot(HaveOccurred())
				// must be the first assertion
				Expect(b.Len()).To(Equal(1 + 8)) // 1 FlagByte + 8 ConnectionID
				firstByte, _ := b.ReadByte()
				Expect(firstByte & 0x01).To(Equal(uint8(1)))
				Expect(firstByte & 0x30).To(BeZero()) // no packet number present
			})

			It("sets the Version Flag for packets sent as a client, and adds a packet number", func() {
				b := &bytes.Buffer{}
				hdr := PublicHeader{
					VersionFlag:     true,
					VersionNumber:   protocol.Version38,
					ConnectionID:    0x4cfa9f9b668619f6,
					PacketNumber:    0x1337,
					PacketNumberLen: protocol.PacketNumberLen6,
				}
				err := hdr.Write(b, protocol.VersionWhatever, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				// must be the first assertion
				Expect(b.Len()).To(Equal(1 + 8 + 4 + 6)) // 1 FlagByte + 8 ConnectionID + 4 version number + 6 PacketNumber
				firstByte, _ := b.ReadByte()
				Expect(firstByte & 0x01).To(Equal(uint8(1)))
				Expect(firstByte & 0x30).To(Equal(uint8(0x30)))
				Expect(string(b.Bytes()[8:12])).To(Equal("Q038"))
				Expect(b.Bytes()[12:18]).To(Equal([]byte{0x37, 0x13, 0, 0, 0, 0}))
			})
		})

		Context("PublicReset packets", func() {
			It("sets the Reset Flag", func() {
				b := &bytes.Buffer{}
				hdr := PublicHeader{
					ResetFlag:    true,
					ConnectionID: 0x4cfa9f9b668619f6,
				}
				err := hdr.Write(b, protocol.VersionWhatever, protocol.PerspectiveServer)
				Expect(err).ToNot(HaveOccurred())
				// must be the first assertion
				Expect(b.Len()).To(Equal(1 + 8)) // 1 FlagByte + 8 ConnectionID
				firstByte, _ := b.ReadByte()
				Expect((firstByte & 0x02) >> 1).To(Equal(uint8(1)))
			})

			It("doesn't add a packet number for headers with Reset Flag sent as a client", func() {
				b := &bytes.Buffer{}
				hdr := PublicHeader{
					ResetFlag:       true,
					ConnectionID:    0x4cfa9f9b668619f6,
					PacketNumber:    2,
					PacketNumberLen: protocol.PacketNumberLen6,
				}
				err := hdr.Write(b, protocol.VersionWhatever, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				// must be the first assertion
				Expect(b.Len()).To(Equal(1 + 8)) // 1 FlagByte + 8 ConnectionID
			})
		})

		Context("GetLength", func() {
			It("errors when calling GetLength for Version Negotiation packets", func() {
				hdr := PublicHeader{VersionFlag: true}
				_, err := hdr.GetLength(protocol.PerspectiveServer)
				Expect(err).To(MatchError(errGetLengthNotForVersionNegotiation))
			})

			It("errors when calling GetLength for packets that have the VersionFlag and the ResetFlag set", func() {
				hdr := PublicHeader{
					ResetFlag:   true,
					VersionFlag: true,
				}
				_, err := hdr.GetLength(protocol.PerspectiveServer)
				Expect(err).To(MatchError(errResetAndVersionFlagSet))
			})

			It("errors when PacketNumberLen is not set", func() {
				hdr := PublicHeader{
					ConnectionID: 0x4cfa9f9b668619f6,
					PacketNumber: 0xDECAFBAD,
				}
				_, err := hdr.GetLength(protocol.PerspectiveServer)
				Expect(err).To(MatchError(errPacketNumberLenNotSet))
			})

			It("gets the length of a packet with longest packet number length and connectionID", func() {
				hdr := PublicHeader{
					ConnectionID:    0x4cfa9f9b668619f6,
					PacketNumber:    0xDECAFBAD,
					PacketNumberLen: protocol.PacketNumberLen6,
				}
				length, err := hdr.GetLength(protocol.PerspectiveServer)
				Expect(err).ToNot(HaveOccurred())
				Expect(length).To(Equal(protocol.ByteCount(1 + 8 + 6))) // 1 byte public flag, 8 bytes connectionID, and packet number
			})

			It("gets the lengths of a packet sent by the client with the VersionFlag set", func() {
				hdr := PublicHeader{
					ConnectionID:         0x4cfa9f9b668619f6,
					TruncateConnectionID: true,
					PacketNumber:         0xDECAFBAD,
					PacketNumberLen:      protocol.PacketNumberLen6,
					VersionFlag:          true,
					VersionNumber:        versionLittleEndian,
				}
				length, err := hdr.GetLength(protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(length).To(Equal(protocol.ByteCount(1 + 4 + 6))) // 1 byte public flag, 4 version number, and packet number
			})

			It("gets the length of a packet with longest packet number length and truncated connectionID", func() {
				hdr := PublicHeader{
					ConnectionID:         0x4cfa9f9b668619f6,
					TruncateConnectionID: true,
					PacketNumber:         0xDECAFBAD,
					PacketNumberLen:      protocol.PacketNumberLen6,
				}
				length, err := hdr.GetLength(protocol.PerspectiveServer)
				Expect(err).ToNot(HaveOccurred())
				Expect(length).To(Equal(protocol.ByteCount(1 + 6))) // 1 byte public flag, and packet number
			})

			It("gets the length of a packet 2 byte packet number length ", func() {
				hdr := PublicHeader{
					ConnectionID:    0x4cfa9f9b668619f6,
					PacketNumber:    0xDECAFBAD,
					PacketNumberLen: protocol.PacketNumberLen2,
				}
				length, err := hdr.GetLength(protocol.PerspectiveServer)
				Expect(err).ToNot(HaveOccurred())
				Expect(length).To(Equal(protocol.ByteCount(1 + 8 + 2))) // 1 byte public flag, 8 byte connectionID, and packet number
			})

			It("works with diversification nonce", func() {
				hdr := PublicHeader{
					DiversificationNonce: []byte("foo"),
					PacketNumberLen:      protocol.PacketNumberLen1,
				}
				length, err := hdr.GetLength(protocol.PerspectiveServer)
				Expect(err).NotTo(HaveOccurred())
				Expect(length).To(Equal(protocol.ByteCount(1 + 8 + 3 + 1))) // 1 byte public flag, 8 byte connectionID, 3 byte DiversificationNonce, 1 byte PacketNumber
			})

			It("gets the length of a PublicReset", func() {
				hdr := PublicHeader{
					ResetFlag:    true,
					ConnectionID: 0x4cfa9f9b668619f6,
				}
				length, err := hdr.GetLength(protocol.PerspectiveServer)
				Expect(err).NotTo(HaveOccurred())
				Expect(length).To(Equal(protocol.ByteCount(1 + 8))) // 1 byte public flag, 8 byte connectionID
			})
		})

		Context("packet number length", func() {
			It("doesn't write a header if the packet number length is not set", func() {
				b := &bytes.Buffer{}
				hdr := PublicHeader{
					ConnectionID: 0x4cfa9f9b668619f6,
					PacketNumber: 0xDECAFBAD,
				}
				err := hdr.Write(b, protocol.VersionWhatever, protocol.PerspectiveServer)
				Expect(err).To(MatchError("PublicHeader: PacketNumberLen not set"))
			})

			Context("in little endian", func() {
				version := protocol.Version37

				BeforeEach(func() {
					Expect(utils.GetByteOrder(version)).To(Equal(utils.LittleEndian))
				})

				It("writes a header with a 1-byte packet number", func() {
					b := &bytes.Buffer{}
					hdr := PublicHeader{
						ConnectionID:    0x4cfa9f9b668619f6,
						PacketNumber:    0xDECAFBAD,
						PacketNumberLen: protocol.PacketNumberLen1,
					}
					err := hdr.Write(b, version, protocol.PerspectiveServer)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()).To(Equal([]byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xAD}))
				})

				It("writes a header with a 2-byte packet number", func() {
					b := &bytes.Buffer{}
					hdr := PublicHeader{
						ConnectionID:    0x4cfa9f9b668619f6,
						PacketNumber:    0xDECAFBAD,
						PacketNumberLen: protocol.PacketNumberLen2,
					}
					err := hdr.Write(b, version, protocol.PerspectiveServer)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()).To(Equal([]byte{0x18, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xad, 0xfb}))
				})

				It("writes a header with a 4-byte packet number", func() {
					b := &bytes.Buffer{}
					hdr := PublicHeader{
						ConnectionID:    0x4cfa9f9b668619f6,
						PacketNumber:    0x13DECAFBAD,
						PacketNumberLen: protocol.PacketNumberLen4,
					}
					err := hdr.Write(b, version, protocol.PerspectiveServer)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()).To(Equal([]byte{0x28, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xAD, 0xfb, 0xca, 0xde}))
				})

				It("writes a header with a 6-byte packet number", func() {
					b := &bytes.Buffer{}
					hdr := PublicHeader{
						ConnectionID:    0x4cfa9f9b668619f6,
						PacketNumber:    0xBE1337DECAFBAD,
						PacketNumberLen: protocol.PacketNumberLen6,
					}
					err := hdr.Write(b, version, protocol.PerspectiveServer)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()).To(Equal([]byte{0x38, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xad, 0xfb, 0xca, 0xde, 0x37, 0x13}))
				})
			})

			Context("in big endian", func() {
				version := protocol.Version39

				BeforeEach(func() {
					Expect(utils.GetByteOrder(version)).To(Equal(utils.BigEndian))
				})

				It("writes a header with a 1-byte packet number", func() {
					b := &bytes.Buffer{}
					hdr := PublicHeader{
						ConnectionID:    0x4cfa9f9b668619f6,
						PacketNumber:    0xdecafbad,
						PacketNumberLen: protocol.PacketNumberLen1,
					}
					err := hdr.Write(b, version, protocol.PerspectiveServer)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()).To(Equal([]byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xad}))
				})

				It("writes a header with a 2-byte packet number", func() {
					b := &bytes.Buffer{}
					hdr := PublicHeader{
						ConnectionID:    0x4cfa9f9b668619f6,
						PacketNumber:    0xdecafbad,
						PacketNumberLen: protocol.PacketNumberLen2,
					}
					err := hdr.Write(b, version, protocol.PerspectiveServer)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()).To(Equal([]byte{0x18, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xfb, 0xad}))
				})

				It("writes a header with a 4-byte packet number", func() {
					b := &bytes.Buffer{}
					hdr := PublicHeader{
						ConnectionID:    0x4cfa9f9b668619f6,
						PacketNumber:    0x13decafbad,
						PacketNumberLen: protocol.PacketNumberLen4,
					}
					err := hdr.Write(b, version, protocol.PerspectiveServer)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()).To(Equal([]byte{0x28, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0xde, 0xca, 0xfb, 0xad}))
				})

				It("writes a header with a 6-byte packet number", func() {
					b := &bytes.Buffer{}
					hdr := PublicHeader{
						ConnectionID:    0x4cfa9f9b668619f6,
						PacketNumber:    0xbe1337decafbad,
						PacketNumberLen: protocol.PacketNumberLen6,
					}
					err := hdr.Write(b, version, protocol.PerspectiveServer)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()).To(Equal([]byte{0x38, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x13, 0x37, 0xde, 0xca, 0xfb, 0xad}))
				})
			})
		})
	})
})
