//go:build go1.21

package qtls

import (
	"crypto/tls"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Go 1.21", func() {
	It("converts to tls.EncryptionLevel", func() {
		Expect(ToTLSEncryptionLevel(protocol.EncryptionInitial)).To(Equal(tls.QUICEncryptionLevelInitial))
		Expect(ToTLSEncryptionLevel(protocol.EncryptionHandshake)).To(Equal(tls.QUICEncryptionLevelHandshake))
		Expect(ToTLSEncryptionLevel(protocol.Encryption1RTT)).To(Equal(tls.QUICEncryptionLevelApplication))
		Expect(ToTLSEncryptionLevel(protocol.Encryption0RTT)).To(Equal(tls.QUICEncryptionLevelEarly))
	})

	It("converts from tls.EncryptionLevel", func() {
		Expect(FromTLSEncryptionLevel(tls.QUICEncryptionLevelInitial)).To(Equal(protocol.EncryptionInitial))
		Expect(FromTLSEncryptionLevel(tls.QUICEncryptionLevelHandshake)).To(Equal(protocol.EncryptionHandshake))
		Expect(FromTLSEncryptionLevel(tls.QUICEncryptionLevelApplication)).To(Equal(protocol.Encryption1RTT))
		Expect(FromTLSEncryptionLevel(tls.QUICEncryptionLevelEarly)).To(Equal(protocol.Encryption0RTT))
	})

	Context("setting up a tls.Config for the client", func() {
		It("sets up a session cache if there's one present on the config", func() {
			csc := tls.NewLRUClientSessionCache(1)
			conf := &QUICConfig{TLSConfig: &tls.Config{ClientSessionCache: csc}}
			SetupConfigForClient(conf, nil, nil)
			Expect(conf.TLSConfig.ClientSessionCache).ToNot(BeNil())
			Expect(conf.TLSConfig.ClientSessionCache).ToNot(Equal(csc))
		})

		It("doesn't set up a session cache if there's none present on the config", func() {
			conf := &QUICConfig{TLSConfig: &tls.Config{}}
			SetupConfigForClient(conf, nil, nil)
			Expect(conf.TLSConfig.ClientSessionCache).To(BeNil())
		})
	})

	Context("setting up a tls.Config for the server", func() {
		It("sets the minimum TLS version to TLS 1.3", func() {
			orig := &tls.Config{MinVersion: tls.VersionTLS12}
			conf := &QUICConfig{TLSConfig: orig}
			SetupConfigForServer(conf, false, nil, nil)
			Expect(conf.TLSConfig.MinVersion).To(BeEquivalentTo(tls.VersionTLS13))
			// check that the original config wasn't modified
			Expect(orig.MinVersion).To(BeEquivalentTo(tls.VersionTLS12))
		})
	})
})
