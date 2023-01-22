package wire

import (
	"encoding/binary"
	mrand "math/rand"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Version Negotiation Packets", func() {
	randConnID := func(l int) protocol.ArbitraryLenConnectionID {
		b := make(protocol.ArbitraryLenConnectionID, l)
		_, err := mrand.Read(b)
		Expect(err).ToNot(HaveOccurred())
		return b
	}

	It("parses a Version Negotiation packet", func() {
		srcConnID := randConnID(rand.Intn(255) + 1)
		destConnID := randConnID(rand.Intn(255) + 1)
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
		dest, src, supportedVersions, err := ParseVersionNegotiationPacket(data)
		Expect(err).ToNot(HaveOccurred())
		Expect(dest).To(Equal(destConnID))
		Expect(src).To(Equal(srcConnID))
		Expect(supportedVersions).To(Equal(versions))
	})

	It("errors if it contains versions of the wrong length", func() {
		connID := protocol.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		versions := []protocol.VersionNumber{0x22334455, 0x33445566}
		data := ComposeVersionNegotiation(connID, connID, versions)
		_, _, _, err := ParseVersionNegotiationPacket(data[:len(data)-2])
		Expect(err).To(MatchError("Version Negotiation packet has a version list with an invalid length"))
	})

	It("errors if the version list is empty", func() {
		connID := protocol.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		versions := []protocol.VersionNumber{0x22334455}
		data := ComposeVersionNegotiation(connID, connID, versions)
		// remove 8 bytes (two versions), since ComposeVersionNegotiation also added a reserved version number
		data = data[:len(data)-8]
		_, _, _, err := ParseVersionNegotiationPacket(data)
		Expect(err).To(MatchError("Version Negotiation packet has empty version list"))
	})

	It("adds a reserved version", func() {
		srcConnID := protocol.ArbitraryLenConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}
		destConnID := protocol.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		versions := []protocol.VersionNumber{1001, 1003}
		data := ComposeVersionNegotiation(destConnID, srcConnID, versions)
		Expect(IsLongHeaderPacket(data[0])).To(BeTrue())
		v, err := ParseVersion(data)
		Expect(err).ToNot(HaveOccurred())
		Expect(v).To(BeZero())
		dest, src, supportedVersions, err := ParseVersionNegotiationPacket(data)
		Expect(err).ToNot(HaveOccurred())
		Expect(dest).To(Equal(destConnID))
		Expect(src).To(Equal(srcConnID))
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
