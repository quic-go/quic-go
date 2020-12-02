package wire

import (
	"bytes"
	"encoding/binary"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Version Negotiation Packets", func() {
	It("parses a Version Negotiation packet", func() {
		srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
		destConnID := protocol.ConnectionID{9, 8, 7, 6, 5, 4, 3, 2, 1}
		versions := []protocol.VersionNumber{0x22334455, 0x33445566}
		data := []byte{0x80, 0, 0, 0, 0}
		data = append(data, uint8(len(destConnID)))
		data = append(data, destConnID...)
		data = append(data, uint8(len(srcConnID)))
		data = append(data, srcConnID...)
		for _, v := range versions {
			data = append(data, []byte{0, 0, 0, 0}...)
			binary.BigEndian.PutUint32(data[len(data)-4:], uint32(v))
		}
		Expect(IsVersionNegotiationPacket(data)).To(BeTrue())
		hdr, supportedVersions, err := ParseVersionNegotiationPacket(bytes.NewReader(data))
		Expect(err).ToNot(HaveOccurred())
		Expect(hdr.DestConnectionID).To(Equal(destConnID))
		Expect(hdr.SrcConnectionID).To(Equal(srcConnID))
		Expect(hdr.IsLongHeader).To(BeTrue())
		Expect(hdr.Version).To(BeZero())
		Expect(supportedVersions).To(Equal(versions))
	})

	It("errors if it contains versions of the wrong length", func() {
		connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		versions := []protocol.VersionNumber{0x22334455, 0x33445566}
		data, err := ComposeVersionNegotiation(connID, connID, versions)
		Expect(err).ToNot(HaveOccurred())
		_, _, err = ParseVersionNegotiationPacket(bytes.NewReader(data[:len(data)-2]))
		Expect(err).To(MatchError("Version Negotiation packet has a version list with an invalid length"))
	})

	It("errors if the version list is empty", func() {
		connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		versions := []protocol.VersionNumber{0x22334455}
		data, err := ComposeVersionNegotiation(connID, connID, versions)
		Expect(err).ToNot(HaveOccurred())
		// remove 8 bytes (two versions), since ComposeVersionNegotiation also added a reserved version number
		data = data[:len(data)-8]
		_, _, err = ParseVersionNegotiationPacket(bytes.NewReader(data))
		Expect(err).To(MatchError("Version Negotiation packet has empty version list"))
	})

	It("adds a reserved version", func() {
		srcConnID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}
		destConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		versions := []protocol.VersionNumber{1001, 1003}
		data, err := ComposeVersionNegotiation(destConnID, srcConnID, versions)
		Expect(err).ToNot(HaveOccurred())
		Expect(data[0] & 0x80).ToNot(BeZero())
		hdr, supportedVersions, err := ParseVersionNegotiationPacket(bytes.NewReader(data))
		Expect(err).ToNot(HaveOccurred())
		Expect(hdr.DestConnectionID).To(Equal(destConnID))
		Expect(hdr.SrcConnectionID).To(Equal(srcConnID))
		Expect(hdr.Version).To(BeZero())
		// the supported versions should include one reserved version number
		Expect(supportedVersions).To(HaveLen(len(versions) + 1))
		for _, v := range versions {
			Expect(supportedVersions).To(ContainElement(v))
		}
		var reservedVersion protocol.VersionNumber
	versionLoop:
		for _, ver := range supportedVersions {
			for _, v := range versions {
				if v == ver {
					continue versionLoop
				}
			}
			reservedVersion = ver
		}
		Expect(reservedVersion).ToNot(BeZero())
		Expect(reservedVersion&0x0f0f0f0f == 0x0a0a0a0a).To(BeTrue()) // check that it's a greased version number
	})
})
