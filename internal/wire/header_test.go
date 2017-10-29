package wire

import (
	"bytes"
	"io"
	"log"
	"os"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Header", func() {
	const (
		versionPublicHeader = protocol.Version39  // a QUIC version that uses the Public Header format
		versionIETFHeader   = protocol.VersionTLS // a QUIC version taht uses the IETF Header format
	)

	Context("peeking the connection ID", func() {
		It("gets the connection ID", func() {
			b := bytes.NewReader([]byte{0x09, 0x4c, 0xfa, 0x9f, 0x9b, 0x66, 0x86, 0x19, 0xf6, 0x51, 0x30, 0x33, 0x34, 0x01})
			len := b.Len()
			connID, err := PeekConnectionID(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(connID).To(Equal(protocol.ConnectionID(0x4cfa9f9b668619f6)))
			Expect(b.Len()).To(Equal(len))
		})

		It("errors if the header is too short", func() {
			b := bytes.NewReader([]byte{0x09, 0xf6, 0x19, 0x86, 0x66, 0x9b})
			_, err := PeekConnectionID(b)
			Expect(err).To(HaveOccurred())
		})

		It("errors if the header is empty", func() {
			b := bytes.NewReader([]byte{})
			_, err := PeekConnectionID(b)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("parsing", func() {
		It("parses an IETF draft header, when the QUIC version supports TLS", func() {
			buf := &bytes.Buffer{}
			// use a short header, which isn't distinguishable from the gQUIC Public Header when looking at the type byte
			err := (&Header{
				IsLongHeader:    false,
				KeyPhase:        1,
				PacketNumber:    0x42,
				PacketNumberLen: protocol.PacketNumberLen2,
			}).writeHeader(buf)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := ParseHeader(bytes.NewReader(buf.Bytes()), protocol.PerspectiveClient, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.KeyPhase).To(BeEquivalentTo(1))
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
			Expect(hdr.isPublicHeader).To(BeFalse())
		})

		It("parses an IETF draft header, when the version is not known, but it has Long Header format", func() {
			buf := &bytes.Buffer{}
			err := (&Header{
				IsLongHeader: true,
				Type:         3,
				PacketNumber: 0x42,
			}).writeHeader(buf)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := ParseHeader(bytes.NewReader(buf.Bytes()), protocol.PerspectiveClient, protocol.VersionUnknown)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(BeEquivalentTo(3))
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
			Expect(hdr.isPublicHeader).To(BeFalse())
		})

		It("parses a gQUIC Public Header, when the version is not known", func() {
			buf := &bytes.Buffer{}
			err := (&Header{
				VersionFlag:     true,
				Version:         versionPublicHeader,
				ConnectionID:    0x42,
				PacketNumber:    0x1337,
				PacketNumberLen: protocol.PacketNumberLen6,
			}).writePublicHeader(buf, protocol.PerspectiveClient, versionPublicHeader)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := ParseHeader(bytes.NewReader(buf.Bytes()), protocol.PerspectiveClient, protocol.VersionUnknown)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x1337)))
			Expect(hdr.Version).To(Equal(versionPublicHeader))
			Expect(hdr.isPublicHeader).To(BeTrue())
		})

		It("parses a gQUIC Public Header, when the version is known", func() {
			buf := &bytes.Buffer{}
			err := (&Header{
				ConnectionID:         0x42,
				PacketNumber:         0x1337,
				PacketNumberLen:      protocol.PacketNumberLen6,
				DiversificationNonce: bytes.Repeat([]byte{'f'}, 32),
			}).writePublicHeader(buf, protocol.PerspectiveServer, versionPublicHeader)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := ParseHeader(bytes.NewReader(buf.Bytes()), protocol.PerspectiveServer, versionPublicHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x1337)))
			Expect(hdr.DiversificationNonce).To(HaveLen(32))
			Expect(hdr.isPublicHeader).To(BeTrue())
		})

		It("errors when parsing the gQUIC header fails", func() {
			buf := &bytes.Buffer{}
			err := (&Header{
				VersionFlag:     true,
				Version:         versionPublicHeader,
				ConnectionID:    0x42,
				PacketNumber:    0x1337,
				PacketNumberLen: protocol.PacketNumberLen6,
			}).writePublicHeader(buf, protocol.PerspectiveClient, versionPublicHeader)
			Expect(err).ToNot(HaveOccurred())
			_, err = ParseHeader(bytes.NewReader(buf.Bytes()[0:12]), protocol.PerspectiveClient, protocol.VersionUnknown)
			Expect(err).To(MatchError(io.EOF))
		})

		It("errors when given no data", func() {
			_, err := ParseHeader(bytes.NewReader([]byte{}), protocol.PerspectiveClient, protocol.VersionUnknown)
			Expect(err).To(MatchError(io.EOF))
		})
	})

	Context("writing", func() {
		It("writes a gQUIC Public Header", func() {
			buf := &bytes.Buffer{}
			hdr := &Header{
				ConnectionID:    0x1337,
				PacketNumber:    0x42,
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			err := hdr.Write(buf, protocol.PerspectiveServer, versionPublicHeader)
			Expect(err).ToNot(HaveOccurred())
			_, err = parsePublicHeader(bytes.NewReader(buf.Bytes()), protocol.PerspectiveServer, versionPublicHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.isPublicHeader).To(BeTrue())
		})

		It("writes a IETF draft header", func() {
			buf := &bytes.Buffer{}
			hdr := &Header{
				ConnectionID:    0x1337,
				PacketNumber:    0x42,
				PacketNumberLen: protocol.PacketNumberLen2,
				KeyPhase:        1,
			}
			err := hdr.Write(buf, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			_, err = parseHeader(bytes.NewReader(buf.Bytes()), protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.isPublicHeader).To(BeFalse())
		})
	})

	Context("getting the length", func() {
		It("get the length of a gQUIC Public Header", func() {
			buf := &bytes.Buffer{}
			hdr := &Header{
				ConnectionID:         0x1337,
				PacketNumber:         0x42,
				PacketNumberLen:      protocol.PacketNumberLen2,
				DiversificationNonce: bytes.Repeat([]byte{'f'}, 32),
			}
			err := hdr.Write(buf, protocol.PerspectiveServer, versionPublicHeader)
			Expect(err).ToNot(HaveOccurred())
			publicHeaderLen, err := hdr.getPublicHeaderLength(protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			ietfHeaderLen, err := hdr.getHeaderLength()
			Expect(err).ToNot(HaveOccurred())
			Expect(publicHeaderLen).ToNot(Equal(ietfHeaderLen)) // make sure we can distinguish between the two header types
			len, err := hdr.GetLength(protocol.PerspectiveServer, versionPublicHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(publicHeaderLen))
		})

		It("get the length of a a IETF draft header", func() {
			buf := &bytes.Buffer{}
			hdr := &Header{
				IsLongHeader:    true,
				ConnectionID:    0x1337,
				PacketNumber:    0x42,
				PacketNumberLen: protocol.PacketNumberLen2,
				KeyPhase:        1,
			}
			err := hdr.Write(buf, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			publicHeaderLen, err := hdr.getPublicHeaderLength(protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			ietfHeaderLen, err := hdr.getHeaderLength()
			Expect(err).ToNot(HaveOccurred())
			Expect(publicHeaderLen).ToNot(Equal(ietfHeaderLen)) // make sure we can distinguish between the two header types
			len, err := hdr.GetLength(protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(ietfHeaderLen))
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

		It("logs an IETF draft header", func() {
			(&Header{
				IsLongHeader: true,
			}).Log()
			Expect(string(buf.Bytes())).To(ContainSubstring("Long Header"))
		})

		It("logs a Public Header", func() {
			(&Header{
				isPublicHeader: true,
			}).Log()
			Expect(string(buf.Bytes())).To(ContainSubstring("Public Header"))
		})
	})
})
