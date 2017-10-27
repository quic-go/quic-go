package wire

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Version Negotiation Packet", func() {
	It("composes version negotiation packets", func() {
		expected := append(
			[]byte{0x01 | 0x08, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
			[]byte{'Q', '0', '9', '9'}...,
		)
		Expect(ComposeVersionNegotiation(1, []protocol.VersionNumber{99})).To(Equal(expected))
	})
})
