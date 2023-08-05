//go:build !go1.21

package qtls

import (
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/quic-go/qtls-go1-20"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Go 1.20", func() {
	It("converts to qtls.EncryptionLevel", func() {
		Expect(ToTLSEncryptionLevel(protocol.EncryptionInitial)).To(Equal(qtls.QUICEncryptionLevelInitial))
		Expect(ToTLSEncryptionLevel(protocol.EncryptionHandshake)).To(Equal(qtls.QUICEncryptionLevelHandshake))
		Expect(ToTLSEncryptionLevel(protocol.Encryption1RTT)).To(Equal(qtls.QUICEncryptionLevelApplication))
		Expect(ToTLSEncryptionLevel(protocol.Encryption0RTT)).To(Equal(qtls.QUICEncryptionLevelEarly))
	})

	It("converts from qtls.EncryptionLevel", func() {
		Expect(FromTLSEncryptionLevel(qtls.QUICEncryptionLevelInitial)).To(Equal(protocol.EncryptionInitial))
		Expect(FromTLSEncryptionLevel(qtls.QUICEncryptionLevelHandshake)).To(Equal(protocol.EncryptionHandshake))
		Expect(FromTLSEncryptionLevel(qtls.QUICEncryptionLevelApplication)).To(Equal(protocol.Encryption1RTT))
		Expect(FromTLSEncryptionLevel(qtls.QUICEncryptionLevelEarly)).To(Equal(protocol.Encryption0RTT))
	})
})
