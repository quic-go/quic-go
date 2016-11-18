package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"runtime"
	"time"

	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cert Manager", func() {
	var cm *certManager

	BeforeEach(func() {
		cm = NewCertManager().(*certManager)
	})

	It("errors when given invalid data", func() {
		err := cm.SetData([]byte("foobar"))
		Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "Certificate data invalid")))
	})

	It("decompresses a certificate chain", func() {
		cert1 := []byte{0xde, 0xca, 0xfb, 0xad}
		cert2 := []byte{0xde, 0xad, 0xbe, 0xef, 0x13, 0x37}
		chain := [][]byte{cert1, cert2}
		compressed, err := compressChain(chain, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		err = cm.SetData(compressed)
		Expect(err).ToNot(HaveOccurred())
		Expect(cm.chain).To(Equal(chain))
	})

	Context("getting the leaf cert", func() {
		It("gets it", func() {
			cert1 := []byte{0xc1}
			cert2 := []byte{0xc2}
			cm.chain = [][]byte{cert1, cert2}
			leafCert := cm.GetLeafCert()
			Expect(leafCert).To(Equal(cert1))
		})

		It("returns nil if the chain hasn't been set yet", func() {
			leafCert := cm.GetLeafCert()
			Expect(leafCert).To(BeNil())
		})
	})

	Context("verifying the server signature", func() {
		It("errors when the chain hasn't been set yet", func() {
			valid, err := cm.VerifyServerProof([]byte("proof"), []byte("chlo"), []byte("scfg"))
			Expect(err).To(MatchError(errNoCertificateChain))
			Expect(valid).To(BeFalse())
		})

		It("errors when it can't parse the certificate", func() {
			cert := []byte("invalid cert")
			cm.chain = [][]byte{cert}
			valid, err := cm.VerifyServerProof([]byte("proof"), []byte("chlo"), []byte("scfg"))
			Expect(err).To(HaveOccurred())
			Expect(err).ToNot(MatchError(errNoCertificateChain))
			Expect(valid).To(BeFalse())
		})
	})

	Context("verifying the certificate chain", func() {
		getCertificate := func(template *x509.Certificate) *x509.Certificate {
			key, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).ToNot(HaveOccurred())

			certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			Expect(err).ToNot(HaveOccurred())
			leafCert, err := x509.ParseCertificate(certDER)
			Expect(err).ToNot(HaveOccurred())
			return leafCert
		}

		It("accepts a valid certificate", func() {
			cc := NewCertChain(testdata.GetTLSConfig()).(*certChain)
			cert, err := cc.getCertForSNI("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
			cm.chain = cert.Certificate
			err = cm.Verify("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors if it can't parse an intermediate certificate", func() {
			cc := NewCertChain(testdata.GetTLSConfig()).(*certChain)
			cert, err := cc.getCertForSNI("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
			cm.chain = cert.Certificate
			Expect(cm.chain).To(HaveLen(2))
			cm.chain[1] = []byte("invalid intermediate")
			err = cm.Verify("quic.clemente.io")
			Expect(err).To(HaveOccurred())
			_, ok := err.(asn1.StructuralError)
			Expect(ok).To(BeTrue())
		})

		It("doesn't accept an expired certificate", func() {
			if runtime.GOOS == "windows" {
				// certificate validation works different on windows, see https://golang.org/src/crypto/x509/verify.go line 238
				Skip("windows")
			}

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now().Add(-25 * time.Hour),
				NotAfter:     time.Now().Add(-time.Hour),
			}
			leafCert := getCertificate(template)

			cm.chain = [][]byte{leafCert.Raw}
			err := cm.Verify("")
			Expect(err).To(HaveOccurred())
			Expect(err.(x509.CertificateInvalidError).Reason).To(Equal(x509.Expired))
		})

		It("doesn't accept a certificate that is not yet valid", func() {
			if runtime.GOOS == "windows" {
				// certificate validation works different on windows, see https://golang.org/src/crypto/x509/verify.go line 238
				Skip("windows")
			}

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now().Add(time.Hour),
				NotAfter:     time.Now().Add(25 * time.Hour),
			}
			leafCert := getCertificate(template)

			cm.chain = [][]byte{leafCert.Raw}
			err := cm.Verify("")
			Expect(err).To(HaveOccurred())
			Expect(err.(x509.CertificateInvalidError).Reason).To(Equal(x509.Expired))
		})

		It("doesn't accept an certificate for the wrong hostname", func() {
			if runtime.GOOS == "windows" {
				// certificate validation works different on windows, see https://golang.org/src/crypto/x509/verify.go line 238
				Skip("windows")
			}

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
				Subject:      pkix.Name{CommonName: "google.com"},
			}
			leafCert := getCertificate(template)

			cm.chain = [][]byte{leafCert.Raw}
			err := cm.Verify("quic.clemente.io")
			Expect(err).To(HaveOccurred())
			_, ok := err.(x509.HostnameError)
			Expect(ok).To(BeTrue())
		})

		It("errors if the chain hasn't been set yet", func() {
			err := cm.Verify("example.com")
			Expect(err).To(HaveOccurred())
		})

		It("errors if it can't parse the leaf certificate", func() {
			cm.chain = [][]byte{[]byte("invalid leaf cert")}
			err := cm.Verify("example.com")
			Expect(err).To(HaveOccurred())
		})

		// this tests relies on LetsEncrypt not being contained in the Root CAs
		It("rejects valid certificate with missing certificate chain", func() {
			if runtime.GOOS == "windows" {
				Skip("LetsEncrypt Root CA is included in Windows")
			}

			cert := testdata.GetCertificate()
			cm.chain = [][]byte{cert.Certificate[0]}
			err := cm.Verify("quic.clemente.io")
			_, ok := err.(x509.UnknownAuthorityError)
			Expect(ok).To(BeTrue())
		})
	})
})
