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

	Context("parsing", func() {
		It("parses an IETF draft Short Header, when the QUIC version supports TLS", func() {
			buf := &bytes.Buffer{}
			// use a short header, which isn't distinguishable from the gQUIC Public Header when looking at the type byte
			err := (&Header{
				IsLongHeader:    false,
				KeyPhase:        1,
				PacketNumber:    0x42,
				PacketNumberLen: protocol.PacketNumberLen2,
			}).writeHeader(buf)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := ParseHeaderSentByClient(bytes.NewReader(buf.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.KeyPhase).To(BeEquivalentTo(1))
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
			Expect(hdr.isPublicHeader).To(BeFalse())
		})

		It("parses an IETF draft header, when the version is not known, but it has Long Header format", func() {
			buf := &bytes.Buffer{}
			err := (&Header{
				IsLongHeader: true,
				Type:         protocol.PacketType0RTT,
				PacketNumber: 0x42,
				Version:      0x1234,
			}).writeHeader(buf)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := ParseHeaderSentByClient(bytes.NewReader(buf.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketType0RTT))
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
			Expect(hdr.isPublicHeader).To(BeFalse())
			Expect(hdr.Version).To(Equal(protocol.VersionNumber(0x1234)))
		})

		It("doens't mistake packets with a Short Header for Version Negotiation Packets", func() {
			// make sure this packet could be mistaken for a Version Negotiation Packet, if we only look at the 0x1 bit
			buf := &bytes.Buffer{}
			err := (&Header{
				IsLongHeader:    false,
				PacketNumberLen: protocol.PacketNumberLen1,
				PacketNumber:    0x42,
			}).writeHeader(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Bytes()[0] & 0x1).To(BeEquivalentTo(0x1))
			hdr, err := ParseHeaderSentByServer(bytes.NewReader(buf.Bytes()), versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
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
			hdr, err := ParseHeaderSentByClient(bytes.NewReader(buf.Bytes()))
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
			hdr, err := ParseHeaderSentByServer(bytes.NewReader(buf.Bytes()), versionPublicHeader)
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
			_, err = ParseHeaderSentByClient(bytes.NewReader(buf.Bytes()[0:12]))
			Expect(err).To(MatchError(io.EOF))
		})

		It("errors when given no data", func() {
			_, err := ParseHeaderSentByServer(bytes.NewReader([]byte{}), protocol.VersionUnknown)
			Expect(err).To(MatchError(io.EOF))
			_, err = ParseHeaderSentByClient(bytes.NewReader([]byte{}))
			Expect(err).To(MatchError(io.EOF))
		})

		It("parses a gQUIC Version Negotiation Packet", func() {
			versions := []protocol.VersionNumber{0x13, 0x37}
			data := ComposeGQUICVersionNegotiation(0x42, versions)
			hdr, err := ParseHeaderSentByServer(bytes.NewReader(data), protocol.VersionUnknown)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.isPublicHeader).To(BeTrue())
			Expect(hdr.ConnectionID).To(Equal(protocol.ConnectionID(0x42)))
			// in addition to the versions, the supported versions might contain a reserved version number
			for _, version := range versions {
				Expect(hdr.SupportedVersions).To(ContainElement(version))
			}
		})

		It("parses an IETF draft style Version Negotiation Packet", func() {
			versions := []protocol.VersionNumber{0x13, 0x37}
			data := ComposeVersionNegotiation(0x42, 0x77, versions)
			hdr, err := ParseHeaderSentByServer(bytes.NewReader(data), protocol.VersionUnknown)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.isPublicHeader).To(BeFalse())
			Expect(hdr.IsVersionNegotiation).To(BeTrue())
			Expect(hdr.ConnectionID).To(Equal(protocol.ConnectionID(0x42)))
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x77)))
			Expect(hdr.Version).To(BeZero())
			// in addition to the versions, the supported versions might contain a reserved version number
			for _, version := range versions {
				Expect(hdr.SupportedVersions).To(ContainElement(version))
			}
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
			_, err = parsePublicHeader(bytes.NewReader(buf.Bytes()), protocol.PerspectiveServer)
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
