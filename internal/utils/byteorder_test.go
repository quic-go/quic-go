package utils

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Byte Order", func() {
	It("says little Little Endian for QUIC 39 and TLS", func() {
		Expect(GetByteOrder(protocol.Version39)).To(Equal(BigEndian))
		Expect(GetByteOrder(protocol.VersionTLS)).To(Equal(BigEndian))
	})
})
