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
	var cert1, cert2 []byte

	BeforeEach(func() {
		cm = NewCertManager().(*certManager)
		key1, err := rsa.GenerateKey(rand.Reader, 512)
		Expect(err).ToNot(HaveOccurred())
		key2, err := rsa.GenerateKey(rand.Reader, 512)
		Expect(err).ToNot(HaveOccurred())
		template := &x509.Certificate{SerialNumber: big.NewInt(1)}
		cert1, err = x509.CreateCertificate(rand.Reader, template, template, &key1.PublicKey, key1)
		Expect(err).ToNot(HaveOccurred())
		cert2, err = x509.CreateCertificate(rand.Reader, template, template, &key2.PublicKey, key2)
		Expect(err).ToNot(HaveOccurred())
	})

	It("errors when given invalid data", func() {
		err := cm.SetData([]byte("foobar"))
		Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "Certificate data invalid")))
	})

	Context("setting the data", func() {
		It("decompresses a certificate chain", func() {
			chain := [][]byte{cert1, cert2}
			compressed, err := compressChain(chain, nil, nil)
			Expect(err).ToNot(HaveOccurred())
			err = cm.SetData(compressed)
			Expect(err).ToNot(HaveOccurred())
			Expect(cm.chain[0].Raw).To(Equal(cert1))
			Expect(cm.chain[1].Raw).To(Equal(cert2))
		})

		It("errors if it can't decompress the chain", func() {
			err := cm.SetData([]byte("invalid data"))
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "Certificate data invalid")))
		})

		It("errors if it can't parse a certificate", func() {
			chain := [][]byte{[]byte("cert1"), []byte("cert2")}
			compressed, err := compressChain(chain, nil, nil)
			Expect(err).ToNot(HaveOccurred())
			err = cm.SetData(compressed)
			_, ok := err.(asn1.StructuralError)
			Expect(ok).To(BeTrue())
		})
	})

	Context("getting the leaf cert", func() {
		It("gets it", func() {
			xcert1, err := x509.ParseCertificate(cert1)
			Expect(err).ToNot(HaveOccurred())
			xcert2, err := x509.ParseCertificate(cert2)
			Expect(err).ToNot(HaveOccurred())
			cm.chain = []*x509.Certificate{xcert1, xcert2}
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
			tlsCert, err := cc.getCertForSNI("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
			for _, data := range tlsCert.Certificate {
				var cert *x509.Certificate
				cert, err = x509.ParseCertificate(data)
				Expect(err).ToNot(HaveOccurred())
				cm.chain = append(cm.chain, cert)
			}
			err = cm.Verify("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
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

			cm.chain = []*x509.Certificate{leafCert}
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

			cm.chain = []*x509.Certificate{leafCert}
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

			cm.chain = []*x509.Certificate{leafCert}
			err := cm.Verify("quic.clemente.io")
			Expect(err).To(HaveOccurred())
			_, ok := err.(x509.HostnameError)
			Expect(ok).To(BeTrue())
		})

		It("errors if the chain hasn't been set yet", func() {
			err := cm.Verify("example.com")
			Expect(err).To(HaveOccurred())
		})

		// this tests relies on LetsEncrypt not being contained in the Root CAs
		It("rejects valid certificate with missing certificate chain", func() {
			if runtime.GOOS == "windows" {
				Skip("LetsEncrypt Root CA is included in Windows")
			}

			cert := testdata.GetCertificate()
			xcert, err := x509.ParseCertificate(cert.Certificate[0])
			Expect(err).ToNot(HaveOccurred())
			cm.chain = []*x509.Certificate{xcert}
			err = cm.Verify("quic.clemente.io")
			_, ok := err.(x509.UnknownAuthorityError)
			Expect(ok).To(BeTrue())
		})
	})
})
