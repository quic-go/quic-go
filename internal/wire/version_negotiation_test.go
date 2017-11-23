package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Version Negotiation Packets", func() {
	It("writes for gQUIC", func() {
		versions := []protocol.VersionNumber{1001, 1003}
		data := ComposeGQUICVersionNegotiation(0x1337, versions)
		hdr, err := parsePublicHeader(bytes.NewReader(data), protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())
		Expect(hdr.VersionFlag).To(BeTrue())
		Expect(hdr.ConnectionID).To(Equal(protocol.ConnectionID(0x1337)))
		Expect(hdr.SupportedVersions).To(Equal(versions))
	})

	It("writes IETF draft style", func() {
		versions := []protocol.VersionNumber{1001, 1003}
		data := ComposeVersionNegotiation(0x1337, 0x42, 0x1234, versions)
		hdr, err := parseHeader(bytes.NewReader(data), protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())
		Expect(hdr.Type).To(Equal(protocol.PacketTypeVersionNegotiation))
		Expect(hdr.ConnectionID).To(Equal(protocol.ConnectionID(0x1337)))
		Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
		Expect(hdr.Version).To(Equal(protocol.VersionNumber(0x1234)))
		Expect(hdr.SupportedVersions).To(Equal(versions))
	})
})
