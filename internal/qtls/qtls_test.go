// +build !go1.15

package qtls

import (
	"crypto/tls"
	"errors"
	"net"
	"unsafe"

	mocktls "github.com/lucas-clemente/quic-go/internal/mocks/tls"

	"github.com/marten-seemann/qtls"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	It("sets MinVersion and MaxVersion", func() {
		tlsConf := &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS12}
		qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil)
		Expect(qtlsConf.MinVersion).To(BeEquivalentTo(tls.VersionTLS13))
		Expect(qtlsConf.MaxVersion).To(BeEquivalentTo(tls.VersionTLS13))
	})

	It("works when called with a nil config", func() {
		qtlsConf := tlsConfigToQtlsConfig(nil, nil)
		Expect(qtlsConf).ToNot(BeNil())
	})

	It("sets the setter and getter function for TLS extensions", func() {
		var get, received bool
		extraConfig := &ExtraConfig{
			GetExtensions:      func(handshakeMessageType uint8) []Extension { get = true; return nil },
			ReceivedExtensions: func(handshakeMessageType uint8, exts []qtls.Extension) { received = true },
		}
		qtlsConf := tlsConfigToQtlsConfig(&tls.Config{}, extraConfig)
		qtlsConf.GetExtensions(10)
		Expect(get).To(BeTrue())
		Expect(received).To(BeFalse())
		qtlsConf.ReceivedExtensions(10, nil)
		Expect(received).To(BeTrue())
	})

	It("sets the Accept0RTT callback", func() {
		qtlsConf := tlsConfigToQtlsConfig(nil, &ExtraConfig{Accept0RTT: func([]byte) bool { return true }})
		Expect(qtlsConf.Accept0RTT).ToNot(BeNil())
		Expect(qtlsConf.Accept0RTT(nil)).To(BeTrue())
	})

	It("sets the Rejected0RTT callback", func() {
		var called bool
		qtlsConf := tlsConfigToQtlsConfig(nil, &ExtraConfig{Rejected0RTT: func() { called = true }})
		Expect(qtlsConf.Rejected0RTT).ToNot(BeNil())
		qtlsConf.Rejected0RTT()
		Expect(called).To(BeTrue())
	})

	It("sets MaxEarlyData", func() {
		qtlsConf := tlsConfigToQtlsConfig(nil, nil)
		Expect(qtlsConf.MaxEarlyData).To(BeZero())
		qtlsConf = tlsConfigToQtlsConfig(nil, &ExtraConfig{MaxEarlyData: 1337})
		Expect(qtlsConf.MaxEarlyData).To(Equal(uint32(1337)))
	})

	It("enables 0-RTT", func() {
		qtlsConf := tlsConfigToQtlsConfig(nil, nil)
		Expect(qtlsConf.Enable0RTT).To(BeFalse())
		qtlsConf = tlsConfigToQtlsConfig(nil, &ExtraConfig{Enable0RTT: true})
		Expect(qtlsConf.Enable0RTT).To(BeTrue())
	})

	It("initializes such that the session ticket key remains constant", func() {
		tlsConf := &tls.Config{}
		qtlsConf1 := tlsConfigToQtlsConfig(tlsConf, nil)
		qtlsConf2 := tlsConfigToQtlsConfig(tlsConf, nil)
		Expect(qtlsConf1.SessionTicketKey).ToNot(BeZero()) // should now contain a random value
		Expect(qtlsConf1.SessionTicketKey).To(Equal(qtlsConf2.SessionTicketKey))
	})

	Context("GetConfigForClient callback", func() {
		It("doesn't set it if absent", func() {
			qtlsConf := tlsConfigToQtlsConfig(nil, nil)
			Expect(qtlsConf.GetConfigForClient).To(BeNil())
		})

		It("returns a Config", func() {
			tlsConf := &tls.Config{
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					return &tls.Config{ServerName: "foo.bar"}, nil
				},
			}
			var received bool
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, &ExtraConfig{ReceivedExtensions: func(uint8, []Extension) { received = true }})
			Expect(qtlsConf.GetConfigForClient).ToNot(BeNil())
			confForClient, err := qtlsConf.GetConfigForClient(nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(confForClient.ServerName).To(Equal("foo.bar"))
			Expect(confForClient).ToNot(BeNil())
			Expect(confForClient.MinVersion).To(BeEquivalentTo(tls.VersionTLS13))
			Expect(confForClient.MaxVersion).To(BeEquivalentTo(tls.VersionTLS13))
			Expect(received).To(BeFalse())
			Expect(confForClient.ReceivedExtensions).ToNot(BeNil())
			confForClient.ReceivedExtensions(10, nil)
			Expect(received).To(BeTrue())
		})

		It("returns errors", func() {
			testErr := errors.New("test")
			tlsConf := &tls.Config{
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					return nil, testErr
				},
			}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil)
			_, err := qtlsConf.GetConfigForClient(nil)
			Expect(err).To(MatchError(testErr))
		})

		It("returns nil when the callback returns nil", func() {
			tlsConf := &tls.Config{
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					return nil, nil
				},
			}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil)
			Expect(qtlsConf.GetConfigForClient(nil)).To(BeNil())
		})
	})

	Context("GetCertificate callback", func() {
		It("returns a certificate", func() {
			tlsConf := &tls.Config{
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return &tls.Certificate{Certificate: [][]byte{[]byte("foo"), []byte("bar")}}, nil
				},
			}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil)
			qtlsCert, err := qtlsConf.GetCertificate(nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(qtlsCert).ToNot(BeNil())
			Expect(qtlsCert.Certificate).To(Equal([][]byte{[]byte("foo"), []byte("bar")}))
		})

		It("doesn't set it if absent", func() {
			qtlsConf := tlsConfigToQtlsConfig(&tls.Config{}, nil)
			Expect(qtlsConf.GetCertificate).To(BeNil())
		})

		It("returns errors", func() {
			tlsConf := &tls.Config{
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return nil, errors.New("test")
				},
			}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil)
			_, err := qtlsConf.GetCertificate(nil)
			Expect(err).To(MatchError("test"))
		})

		It("returns nil when the callback returns nil", func() {
			tlsConf := &tls.Config{
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return nil, nil
				},
			}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil)
			Expect(qtlsConf.GetCertificate(nil)).To(BeNil())
		})
	})

	Context("ClientSessionCache", func() {
		It("doesn't set if absent", func() {
			qtlsConf := tlsConfigToQtlsConfig(&tls.Config{}, nil)
			Expect(qtlsConf.ClientSessionCache).To(BeNil())
		})

		It("puts a nil session state", func() {
			csc := mocktls.NewMockClientSessionCache(mockCtrl)
			tlsConf := &tls.Config{ClientSessionCache: csc}
			qtlsConf := tlsConfigToQtlsConfig(tlsConf, nil)
			// put something
			csc.EXPECT().Put("foobar", nil)
			qtlsConf.ClientSessionCache.Put("foobar", nil)
		})
	})
})

var _ = Describe("Config generation", func() {
	It("converts a ClientHelloInfo to a tls.ClientHelloInfo", func() {
		chi := &qtlsClientHelloInfo{
			CipherSuites:      []uint16{1, 2, 3},
			ServerName:        "foo.bar",
			SupportedCurves:   []tls.CurveID{4, 5, 6},
			SupportedPoints:   []uint8{7, 8, 9},
			SignatureSchemes:  []tls.SignatureScheme{10, 11, 12},
			SupportedProtos:   []string{"foo", "bar"},
			SupportedVersions: []uint16{13, 14, 15},
			Conn:              &net.UDPConn{},
			config: &Config{
				MinVersion:       tls.VersionTLS10,
				MaxVersion:       tls.VersionTLS12,
				CipherSuites:     []uint16{16, 17, 18},
				CurvePreferences: []tls.CurveID{19, 20, 21},
			},
		}
		tlsCHI := toTLSClientHelloInfo((*ClientHelloInfo)(unsafe.Pointer(chi)))
		Expect(tlsCHI.CipherSuites).To(Equal([]uint16{1, 2, 3}))
		Expect(tlsCHI.ServerName).To(Equal("foo.bar"))
		Expect(tlsCHI.SupportedCurves).To(Equal([]tls.CurveID{4, 5, 6}))
		Expect(tlsCHI.SupportedPoints).To(Equal([]uint8{7, 8, 9}))
		Expect(tlsCHI.SignatureSchemes).To(Equal([]tls.SignatureScheme{10, 11, 12}))
		Expect(tlsCHI.SupportedProtos).To(Equal([]string{"foo", "bar"}))
		Expect(tlsCHI.SupportedVersions).To(Equal([]uint16{13, 14, 15}))
		Expect(tlsCHI.Conn).To(Equal(&net.UDPConn{}))
		c := (*clientHelloInfo)(unsafe.Pointer(tlsCHI))
		Expect(c.config.CipherSuites).To(Equal([]uint16{16, 17, 18}))
		Expect(c.config.MinVersion).To(BeEquivalentTo(tls.VersionTLS10))
		Expect(c.config.MaxVersion).To(BeEquivalentTo(tls.VersionTLS12))
		Expect(c.config.CurvePreferences).To(Equal([]tls.CurveID{19, 20, 21}))
	})

	It("converts a ClientHelloInfo to a tls.ClientHelloInfo, if no config is set", func() {
		chi := &qtlsClientHelloInfo{CipherSuites: []uint16{13, 37}}
		tlsCHI := toTLSClientHelloInfo((*ClientHelloInfo)(unsafe.Pointer(chi)))
		Expect(tlsCHI.CipherSuites).To(Equal([]uint16{13, 37}))
	})
})
