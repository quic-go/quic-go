package qtls

import (
	"crypto/tls"
	"net"
	"reflect"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("interface go crypto/tls", func() {
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
			conf := &tls.QUICConfig{TLSConfig: &tls.Config{ClientSessionCache: csc}}
			SetupConfigForClient(conf, nil, nil)
			Expect(conf.TLSConfig.ClientSessionCache).ToNot(BeNil())
			Expect(conf.TLSConfig.ClientSessionCache).ToNot(Equal(csc))
		})

		It("doesn't set up a session cache if there's none present on the config", func() {
			conf := &tls.QUICConfig{TLSConfig: &tls.Config{}}
			SetupConfigForClient(conf, nil, nil)
			Expect(conf.TLSConfig.ClientSessionCache).To(BeNil())
		})
	})

	Context("setting up a tls.Config for the server", func() {
		var (
			local  = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42}
			remote = &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
		)

		It("sets the minimum TLS version to TLS 1.3", func() {
			orig := &tls.Config{MinVersion: tls.VersionTLS12}
			conf := SetupConfigForServer(orig, local, remote, nil, nil)
			Expect(conf.MinVersion).To(BeEquivalentTo(tls.VersionTLS13))
			// check that the original config wasn't modified
			Expect(orig.MinVersion).To(BeEquivalentTo(tls.VersionTLS12))
		})

		It("wraps GetCertificate", func() {
			var localAddr, remoteAddr net.Addr
			tlsConf := &tls.Config{
				GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					localAddr = info.Conn.LocalAddr()
					remoteAddr = info.Conn.RemoteAddr()
					return &tls.Certificate{}, nil
				},
			}
			conf := SetupConfigForServer(tlsConf, local, remote, nil, nil)
			_, err := conf.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(localAddr).To(Equal(local))
			Expect(remoteAddr).To(Equal(remote))
		})

		It("wraps GetConfigForClient", func() {
			var localAddr, remoteAddr net.Addr
			tlsConf := SetupConfigForServer(
				&tls.Config{
					GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
						localAddr = info.Conn.LocalAddr()
						remoteAddr = info.Conn.RemoteAddr()
						return &tls.Config{}, nil
					},
				},
				local,
				remote,
				nil,
				nil,
			)
			conf, err := tlsConf.GetConfigForClient(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(localAddr).To(Equal(local))
			Expect(remoteAddr).To(Equal(remote))
			Expect(conf).ToNot(BeNil())
			Expect(conf.MinVersion).To(BeEquivalentTo(tls.VersionTLS13))
		})

		It("wraps GetConfigForClient, recursively", func() {
			var localAddr, remoteAddr net.Addr
			tlsConf := &tls.Config{}
			var innerConf *tls.Config
			getCert := func(info *tls.ClientHelloInfo) (*tls.Certificate, error) { //nolint:unparam
				localAddr = info.Conn.LocalAddr()
				remoteAddr = info.Conn.RemoteAddr()
				return &tls.Certificate{}, nil
			}
			tlsConf.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				innerConf = tlsConf.Clone()
				// set the MaxVersion, so we can check that quic-go doesn't overwrite the user's config
				innerConf.MaxVersion = tls.VersionTLS12
				innerConf.GetCertificate = getCert
				return innerConf, nil
			}
			tlsConf = SetupConfigForServer(tlsConf, local, remote, nil, nil)
			conf, err := tlsConf.GetConfigForClient(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(conf).ToNot(BeNil())
			Expect(conf.MinVersion).To(BeEquivalentTo(tls.VersionTLS13))
			_, err = conf.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(localAddr).To(Equal(local))
			Expect(remoteAddr).To(Equal(remote))
			// make sure that the tls.Config returned by GetConfigForClient isn't modified
			Expect(reflect.ValueOf(innerConf.GetCertificate).Pointer() == reflect.ValueOf(getCert).Pointer()).To(BeTrue())
			Expect(innerConf.MaxVersion).To(BeEquivalentTo(tls.VersionTLS12))
		})
	})
})
