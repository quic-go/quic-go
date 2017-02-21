package publicheader

import (
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Version Negotation Packets", func() {
	It("composes version negotiation packets", func() {
		expected := append(
			[]byte{0x01 | 0x08, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			protocol.SupportedVersionsAsTags...,
		)
		Expect(ComposeVersionNegotiation(1)).To(Equal(expected))
	})
})
