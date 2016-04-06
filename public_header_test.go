package quic

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Public Header", func() {
	It("parses intial client header", func() {
		b := bytes.NewReader([]byte{0xd, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x51, 0x30, 0x33, 0x30, 0x1})
		publicHeader, err := ParsePublicHeader(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(publicHeader.VersionFlag).To(BeTrue())
		Expect(publicHeader.ResetFlag).To(BeFalse())
		Expect(publicHeader.ConnectionIDLength).To(Equal(uint8(8)))
		Expect(publicHeader.ConnectionID).ToNot(BeZero())
		Expect(publicHeader.QuicVersion).To(Equal(uint32(0x51303330)))
		Expect(publicHeader.PacketNumberLength).To(Equal(uint8(1)))
		Expect(publicHeader.PacketNumber).To(Equal(uint64(1)))
	})
})
