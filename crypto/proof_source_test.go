package crypto

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/asn1"
	"math/big"

	"github.com/lucas-clemente/quic-go/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type ecdsaSignature struct {
	R, S *big.Int
}

var _ = Describe("ProofRsa", func() {
	It("compresses certs", func() {
		cert := []byte{0xde, 0xca, 0xfb, 0xad}
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, certDictZlib)
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert)
		z.Close()
		kd := &proofSource{
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

	Context("when using RSA", func() {
		It("gives valid signatures", func() {
			key := testdata.GetTLSConfig().Certificates[0].PrivateKey.(*rsa.PrivateKey).Public().(*rsa.PublicKey)
			kd, err := NewProofSource(testdata.GetTLSConfig())
			Expect(err).ToNot(HaveOccurred())
			signature, err := kd.SignServerProof("", []byte{'C', 'H', 'L', 'O'}, []byte{'S', 'C', 'F', 'G'})
			Expect(err).ToNot(HaveOccurred())
			// Generated with:
			// ruby -e 'require "digest"; p Digest::SHA256.digest("QUIC CHLO and server config signature\x00" + "\x20\x00\x00\x00" + Digest::SHA256.digest("CHLO") + "SCFG")'
			data := []byte("W\xA6\xFC\xDE\xC7\xD2>c\xE6\xB5\xF6\tq\x9E|<~1\xA33\x01\xCA=\x19\xBD\xC1\xE4\xB0\xBA\x9B\x16%")
			err = rsa.VerifyPSS(key, crypto.SHA256, data, signature, &rsa.PSSOptions{SaltLength: 32})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("when using ECDSA", func() {
		var (
			key    crypto.Signer
			config *tls.Config
		)

		BeforeEach(func() {
			var err error
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			config = &tls.Config{
				Certificates: []tls.Certificate{
					{PrivateKey: key},
				},
			}
		})

		It("gives valid signatures", func() {
			kd, err := NewProofSource(config)
			Expect(err).ToNot(HaveOccurred())
			signature, err := kd.SignServerProof("", []byte{'C', 'H', 'L', 'O'}, []byte{'S', 'C', 'F', 'G'})
			Expect(err).ToNot(HaveOccurred())
			// Generated with:
			// ruby -e 'require "digest"; p Digest::SHA256.digest("QUIC CHLO and server config signature\x00" + "\x20\x00\x00\x00" + Digest::SHA256.digest("CHLO") + "SCFG")'
			data := []byte("W\xA6\xFC\xDE\xC7\xD2>c\xE6\xB5\xF6\tq\x9E|<~1\xA33\x01\xCA=\x19\xBD\xC1\xE4\xB0\xBA\x9B\x16%")
			s := &ecdsaSignature{}
			_, err = asn1.Unmarshal(signature, s)
			Expect(err).NotTo(HaveOccurred())
			b := ecdsa.Verify(key.Public().(*ecdsa.PublicKey), data, s.R, s.S)
			Expect(b).To(BeTrue())
		})
	})

	Context("retrieving certificate", func() {
		var (
			signer *proofSource
			config *tls.Config
			cert   tls.Certificate
		)

		BeforeEach(func() {
			cert = testdata.GetCertificate()
			config = &tls.Config{}
			signer = &proofSource{config: config}
		})

		It("errors without certificates", func() {
			_, err := signer.getCertForSNI("")
			Expect(err).To(MatchError("no matching certificate found"))
		})

		It("uses first certificate in config.Certificates", func() {
			config.Certificates = []tls.Certificate{cert}
			cert, err := signer.getCertForSNI("")
			Expect(err).ToNot(HaveOccurred())
			Expect(cert.PrivateKey).ToNot(BeNil())
			Expect(cert.Certificate[0]).ToNot(BeNil())
		})

		It("uses NameToCertificate entries", func() {
			config.NameToCertificate = map[string]*tls.Certificate{
				"quic.clemente.io": &cert,
			}
			cert, err := signer.getCertForSNI("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
			Expect(cert.PrivateKey).ToNot(BeNil())
			Expect(cert.Certificate[0]).ToNot(BeNil())
		})

		It("uses NameToCertificate entries with wildcard", func() {
			config.NameToCertificate = map[string]*tls.Certificate{
				"*.clemente.io": &cert,
			}
			cert, err := signer.getCertForSNI("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
			Expect(cert.PrivateKey).ToNot(BeNil())
			Expect(cert.Certificate[0]).ToNot(BeNil())
		})

		It("uses GetCertificate", func() {
			config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				Expect(clientHello.ServerName).To(Equal("quic.clemente.io"))
				return &cert, nil
			}
			cert, err := signer.getCertForSNI("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
			Expect(cert.PrivateKey).ToNot(BeNil())
			Expect(cert.Certificate[0]).ToNot(BeNil())
		})

		It("gets leaf certificates", func() {
			config.Certificates = []tls.Certificate{cert}
			cert2, err := signer.GetLeafCert("")
			Expect(err).ToNot(HaveOccurred())
			Expect(cert2).To(Equal(cert.Certificate[0]))
		})
	})
})
