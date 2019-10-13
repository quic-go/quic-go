package handshake

import (
	"crypto/tls"
	"errors"

	gomock "github.com/golang/mock/gomock"
	"github.com/marten-seemann/qtls"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockExtensionHandler struct {
	get, received bool
}

var _ tlsExtensionHandler = &mockExtensionHandler{}

func (h *mockExtensionHandler) GetExtensions(msgType uint8) []qtls.Extension {
	h.get = true
	return nil
}
func (h *mockExtensionHandler) ReceivedExtensions(msgType uint8, exts []qtls.Extension) {
	h.received = true
}
func (*mockExtensionHandler) TransportParameters() <-chan []byte { panic("not implemented") }

var _ = Describe("qtls.Config generation", func() {
	It("sets MinVersion and MaxVersion", func() {
		tlsConf := &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS12}
		qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{})
		Expect(qtlsConf.MinVersion).To(BeEquivalentTo(tls.VersionTLS13))
		Expect(qtlsConf.MaxVersion).To(BeEquivalentTo(tls.VersionTLS13))
	})

	It("works when called with a nil config", func() {
		qtlsConf := tlsConfigToQtlsConfig(nil, nil, &mockExtensionHandler{})
		Expect(qtlsConf).ToNot(BeNil())
	})

	It("sets the setter and getter function for TLS extensions", func() {
		extHandler := &mockExtensionHandler{}
		qtlsConf := tlsConfigToQtlsConfig(&tls.Config{}, nil, extHandler)
		Expect(extHandler.get).To(BeFalse())
		qtlsConf.GetExtensions(10)
		Expect(extHandler.get).To(BeTrue())
		Expect(extHandler.received).To(BeFalse())
		qtlsConf.ReceivedExtensions(10, nil)
		Expect(extHandler.received).To(BeTrue())
	})

	It("initializes such that the session ticket key remains constant", func() {
		tlsConf := &tls.Config{}
		qtlsConf1 := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{})
		qtlsConf2 := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{})
		Expect(qtlsConf1.SessionTicketKey).ToNot(BeZero()) // should now contain a random value
		Expect(qtlsConf1.SessionTicketKey).To(Equal(qtlsConf2.SessionTicketKey))
	})

	Context("GetConfigForClient callback", func() {
		It("doesn't set it if absent", func() {
			qtlsConf := tlsConfigToQtlsConfig(&tls.Config{}, nil, &mockExtensionHandler{})
			Expect(qtlsConf.GetConfigForClient).To(BeNil())
		})

		It("returns a qtls.Config", func() {
			tlsConf := &tls.Config{
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					return &tls.Config{ServerName: "foo.bar"}, nil
				},
			}
			extHandler := &mockExtensionHandler{}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil, extHandler)
			Expect(qtlsConf.GetConfigForClient).ToNot(BeNil())
			confForClient, err := qtlsConf.GetConfigForClient(nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(confForClient.ServerName).To(Equal("foo.bar"))
			Expect(confForClient).ToNot(BeNil())
			Expect(confForClient.MinVersion).To(BeEquivalentTo(tls.VersionTLS13))
			Expect(confForClient.MaxVersion).To(BeEquivalentTo(tls.VersionTLS13))
			Expect(extHandler.get).To(BeFalse())
			confForClient.GetExtensions(10)
			Expect(extHandler.get).To(BeTrue())
		})

		It("returns errors", func() {
			testErr := errors.New("test")
			tlsConf := &tls.Config{
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					return nil, testErr
				},
			}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{})
			_, err := qtlsConf.GetConfigForClient(nil)
			Expect(err).To(MatchError(testErr))
		})

		It("returns nil when the callback returns nil", func() {
			tlsConf := &tls.Config{
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					return nil, nil
				},
			}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{})
			Expect(qtlsConf.GetConfigForClient(nil)).To(BeNil())
		})
	})

	Context("ClientSessionCache", func() {
		It("doesn't set if absent", func() {
			qtlsConf := tlsConfigToQtlsConfig(&tls.Config{}, nil, &mockExtensionHandler{})
			Expect(qtlsConf.ClientSessionCache).To(BeNil())
		})

		It("sets it, and puts and gets session states", func() {
			csc := NewMockClientSessionCache(mockCtrl)
			tlsConf := &tls.Config{ClientSessionCache: csc}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{})
			Expect(qtlsConf.ClientSessionCache).ToNot(BeNil())
			// put something
			csc.EXPECT().Put("foobar", gomock.Any())
			qtlsConf.ClientSessionCache.Put("foobar", &qtls.ClientSessionState{})
			// get something
			csc.EXPECT().Get("raboof").Return(nil, true)
			_, ok := qtlsConf.ClientSessionCache.Get("raboof")
			Expect(ok).To(BeTrue())
		})

		It("puts a nil session state", func() {
			csc := NewMockClientSessionCache(mockCtrl)
			tlsConf := &tls.Config{ClientSessionCache: csc}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{})
			// put something
			csc.EXPECT().Put("foobar", nil)
			qtlsConf.ClientSessionCache.Put("foobar", nil)
		})
	})
})
