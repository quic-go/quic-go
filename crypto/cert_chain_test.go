package crypto

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto/tls"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Proof", func() {

	It("compresses certs", func() {
		cert := []byte{0xde, 0xca, 0xfb, 0xad}
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, certDictZlib)
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert)
		z.Close()
		kd := &certChain{
			config: &tls.Config{
				Certificates: []tls.Certificate{
					{Certificate: [][]byte{cert}},
				},
			},
		}
		certCompressed, err := kd.GetCertsCompressed("", nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(certCompressed).To(Equal(append([]byte{
			0x01, 0x00,
			0x08, 0x00, 0x00, 0x00,
		}, certZlib.Bytes()...)))
	})

	// Context("retrieving certificate", func() {
	// 	var (
	// 		signer *proofSource
	// 		config *tls.Config
	// 		cert   tls.Certificate
	// 	)
	//
	// 	BeforeEach(func() {
	// 		cert = testdata.GetCertificate()
	// 		config = &tls.Config{}
	// 		signer = &proofSource{config: config}
	// 	})
	//
	// 	It("errors without certificates", func() {
	// 		_, err := signer.getCertForSNI("")
	// 		Expect(err).To(MatchError("no matching certificate found"))
	// 	})
	//
	// 	It("uses first certificate in config.Certificates", func() {
	// 		config.Certificates = []tls.Certificate{cert}
	// 		cert, err := signer.getCertForSNI("")
	// 		Expect(err).ToNot(HaveOccurred())
	// 		Expect(cert.PrivateKey).ToNot(BeNil())
	// 		Expect(cert.Certificate[0]).ToNot(BeNil())
	// 	})
	//
	// 	It("uses NameToCertificate entries", func() {
	// 		config.NameToCertificate = map[string]*tls.Certificate{
	// 			"quic.clemente.io": &cert,
	// 		}
	// 		cert, err := signer.getCertForSNI("quic.clemente.io")
	// 		Expect(err).ToNot(HaveOccurred())
	// 		Expect(cert.PrivateKey).ToNot(BeNil())
	// 		Expect(cert.Certificate[0]).ToNot(BeNil())
	// 	})
	//
	// 	It("uses NameToCertificate entries with wildcard", func() {
	// 		config.NameToCertificate = map[string]*tls.Certificate{
	// 			"*.clemente.io": &cert,
	// 		}
	// 		cert, err := signer.getCertForSNI("quic.clemente.io")
	// 		Expect(err).ToNot(HaveOccurred())
	// 		Expect(cert.PrivateKey).ToNot(BeNil())
	// 		Expect(cert.Certificate[0]).ToNot(BeNil())
	// 	})
	//
	// 	It("uses GetCertificate", func() {
	// 		config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// 			Expect(clientHello.ServerName).To(Equal("quic.clemente.io"))
	// 			return &cert, nil
	// 		}
	// 		cert, err := signer.getCertForSNI("quic.clemente.io")
	// 		Expect(err).ToNot(HaveOccurred())
	// 		Expect(cert.PrivateKey).ToNot(BeNil())
	// 		Expect(cert.Certificate[0]).ToNot(BeNil())
	// 	})
	//
	// 	It("gets leaf certificates", func() {
	// 		config.Certificates = []tls.Certificate{cert}
	// 		cert2, err := signer.GetLeafCert("")
	// 		Expect(err).ToNot(HaveOccurred())
	// 		Expect(cert2).To(Equal(cert.Certificate[0]))
	// 	})
	// })
})
