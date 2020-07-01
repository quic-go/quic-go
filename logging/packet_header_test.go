package logging

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Header", func() {
	Context("determining the packet type from the header", func() {
		It("recognizes Initial packets", func() {
			Expect(PacketTypeFromHeader(&wire.Header{
				IsLongHeader: true,
				Type:         protocol.PacketTypeInitial,
				Version:      protocol.VersionTLS,
			})).To(Equal(PacketTypeInitial))
		})

		It("recognizes Handshake packets", func() {
			Expect(PacketTypeFromHeader(&wire.Header{
				IsLongHeader: true,
				Type:         protocol.PacketTypeHandshake,
				Version:      protocol.VersionTLS,
			})).To(Equal(PacketTypeHandshake))
		})

		It("recognizes Retry packets", func() {
			Expect(PacketTypeFromHeader(&wire.Header{
				IsLongHeader: true,
				Type:         protocol.PacketTypeRetry,
				Version:      protocol.VersionTLS,
			})).To(Equal(PacketTypeRetry))
		})

		It("recognizes 0-RTT packets", func() {
			Expect(PacketTypeFromHeader(&wire.Header{
				IsLongHeader: true,
				Type:         protocol.PacketType0RTT,
				Version:      protocol.VersionTLS,
			})).To(Equal(PacketType0RTT))
		})

		It("recognizes Version Negotiation packets", func() {
			Expect(PacketTypeFromHeader(&wire.Header{IsLongHeader: true})).To(Equal(PacketTypeVersionNegotiation))
		})

		It("recognizes 1-RTT packets", func() {
			Expect(PacketTypeFromHeader(&wire.Header{})).To(Equal(PacketType1RTT))
		})

		It("handles unrecognized packet types", func() {
			Expect(PacketTypeFromHeader(&wire.Header{
				IsLongHeader: true,
				Version:      protocol.VersionTLS,
			})).To(Equal(PacketTypeNotDetermined))
		})
	})
})
