package logging_test

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	. "github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Header", func() {
	Context("determining the packet type from the header", func() {
		It("recognizes Initial packets", func() {
			Expect(PacketTypeFromHeader(&wire.Header{
				Type:    protocol.PacketTypeInitial,
				Version: protocol.Version1,
			})).To(Equal(PacketTypeInitial))
		})

		It("recognizes Handshake packets", func() {
			Expect(PacketTypeFromHeader(&wire.Header{
				Type:    protocol.PacketTypeHandshake,
				Version: protocol.Version1,
			})).To(Equal(PacketTypeHandshake))
		})

		It("recognizes Retry packets", func() {
			Expect(PacketTypeFromHeader(&wire.Header{
				Type:    protocol.PacketTypeRetry,
				Version: protocol.Version1,
			})).To(Equal(PacketTypeRetry))
		})

		It("recognizes 0-RTT packets", func() {
			Expect(PacketTypeFromHeader(&wire.Header{
				Type:    protocol.PacketType0RTT,
				Version: protocol.Version1,
			})).To(Equal(PacketType0RTT))
		})

		It("recognizes Version Negotiation packets", func() {
			Expect(PacketTypeFromHeader(&wire.Header{})).To(Equal(PacketTypeVersionNegotiation))
		})

		It("handles unrecognized packet types", func() {
			Expect(PacketTypeFromHeader(&wire.Header{Version: protocol.Version1})).To(Equal(PacketTypeNotDetermined))
		})
	})
})
