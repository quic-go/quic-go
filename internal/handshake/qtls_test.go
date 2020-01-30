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
		qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{}, nil, nil, nil, nil, false)
		Expect(qtlsConf.MinVersion).To(BeEquivalentTo(tls.VersionTLS13))
		Expect(qtlsConf.MaxVersion).To(BeEquivalentTo(tls.VersionTLS13))
	})

	It("works when called with a nil config", func() {
		qtlsConf := tlsConfigToQtlsConfig(nil, nil, &mockExtensionHandler{}, nil, nil, nil, nil, false)
		Expect(qtlsConf).ToNot(BeNil())
	})

	It("sets the setter and getter function for TLS extensions", func() {
		extHandler := &mockExtensionHandler{}
		qtlsConf := tlsConfigToQtlsConfig(&tls.Config{}, nil, extHandler, nil, nil, nil, nil, false)
		Expect(extHandler.get).To(BeFalse())
		qtlsConf.GetExtensions(10)
		Expect(extHandler.get).To(BeTrue())
		Expect(extHandler.received).To(BeFalse())
		qtlsConf.ReceivedExtensions(10, nil)
		Expect(extHandler.received).To(BeTrue())
	})

	It("sets the Accept0RTT callback", func() {
		accept0RTT := func([]byte) bool { return true }
		qtlsConf := tlsConfigToQtlsConfig(nil, nil, &mockExtensionHandler{}, nil, nil, accept0RTT, nil, false)
		Expect(qtlsConf.Accept0RTT).ToNot(BeNil())
		Expect(qtlsConf.Accept0RTT(nil)).To(BeTrue())
	})

	It("sets the Accept0RTT callback", func() {
		var called bool
		rejected0RTT := func() { called = true }
		qtlsConf := tlsConfigToQtlsConfig(nil, nil, &mockExtensionHandler{}, nil, nil, nil, rejected0RTT, false)
		Expect(qtlsConf.Rejected0RTT).ToNot(BeNil())
		qtlsConf.Rejected0RTT()
		Expect(called).To(BeTrue())
	})

	It("enables 0-RTT", func() {
		qtlsConf := tlsConfigToQtlsConfig(nil, nil, &mockExtensionHandler{}, nil, nil, nil, nil, false)
		Expect(qtlsConf.Enable0RTT).To(BeFalse())
		Expect(qtlsConf.MaxEarlyData).To(BeZero())
		qtlsConf = tlsConfigToQtlsConfig(nil, nil, &mockExtensionHandler{}, nil, nil, nil, nil, true)
		Expect(qtlsConf.Enable0RTT).To(BeTrue())
		Expect(qtlsConf.MaxEarlyData).To(Equal(uint32(0xffffffff)))
	})

	It("initializes such that the session ticket key remains constant", func() {
		tlsConf := &tls.Config{}
		qtlsConf1 := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{}, nil, nil, nil, nil, false)
		qtlsConf2 := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{}, nil, nil, nil, nil, false)
		Expect(qtlsConf1.SessionTicketKey).ToNot(BeZero()) // should now contain a random value
		Expect(qtlsConf1.SessionTicketKey).To(Equal(qtlsConf2.SessionTicketKey))
	})

	Context("GetConfigForClient callback", func() {
		It("doesn't set it if absent", func() {
			qtlsConf := tlsConfigToQtlsConfig(&tls.Config{}, nil, &mockExtensionHandler{}, nil, nil, nil, nil, false)
			Expect(qtlsConf.GetConfigForClient).To(BeNil())
		})

		It("returns a qtls.Config", func() {
			tlsConf := &tls.Config{
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					return &tls.Config{ServerName: "foo.bar"}, nil
				},
			}
			extHandler := &mockExtensionHandler{}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil, extHandler, nil, nil, nil, nil, false)
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
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{}, nil, nil, nil, nil, false)
			_, err := qtlsConf.GetConfigForClient(nil)
			Expect(err).To(MatchError(testErr))
		})

		It("returns nil when the callback returns nil", func() {
			tlsConf := &tls.Config{
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					return nil, nil
				},
			}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{}, nil, nil, nil, nil, false)
			Expect(qtlsConf.GetConfigForClient(nil)).To(BeNil())
		})
	})

	Context("ClientSessionCache", func() {
		It("doesn't set if absent", func() {
			qtlsConf := tlsConfigToQtlsConfig(&tls.Config{}, nil, &mockExtensionHandler{}, nil, nil, nil, nil, false)
			Expect(qtlsConf.ClientSessionCache).To(BeNil())
		})

		It("sets it, and puts and gets session states", func() {
			csc := NewMockClientSessionCache(mockCtrl)
			tlsConf := &tls.Config{ClientSessionCache: csc}
			var appData []byte
			qtlsConf := tlsConfigToQtlsConfig(
				tlsConf,
				nil,
				&mockExtensionHandler{},
				func() []byte { return []byte("foobar") },
				func(p []byte) { appData = p },
				nil,
				nil,
				false,
			)
			Expect(qtlsConf.ClientSessionCache).ToNot(BeNil())

			var state *tls.ClientSessionState
			// put something
			csc.EXPECT().Put("localhost", gomock.Any()).Do(func(_ string, css *tls.ClientSessionState) {
				state = css
			})
			qtlsConf.ClientSessionCache.Put("localhost", &qtls.ClientSessionState{})
			// get something
			csc.EXPECT().Get("localhost").Return(state, true)
			_, ok := qtlsConf.ClientSessionCache.Get("localhost")
			Expect(ok).To(BeTrue())
			Expect(appData).To(Equal([]byte("foobar")))
		})

		It("puts a nil session state", func() {
			csc := NewMockClientSessionCache(mockCtrl)
			tlsConf := &tls.Config{ClientSessionCache: csc}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil, &mockExtensionHandler{}, nil, nil, nil, nil, false)
			// put something
			csc.EXPECT().Put("foobar", nil)
			qtlsConf.ClientSessionCache.Put("foobar", nil)
		})
	})
})
