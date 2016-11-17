package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/asn1"

	"github.com/lucas-clemente/quic-go/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Proof", func() {
	Context("when using RSA", func() {
		It("gives valid signatures", func() {
			key := &testdata.GetTLSConfig().Certificates[0]
			signature, err := signServerProof(key, []byte{'C', 'H', 'L', 'O'}, []byte{'S', 'C', 'F', 'G'})
			Expect(err).ToNot(HaveOccurred())
			// Generated with:
			// ruby -e 'require "digest"; p Digest::SHA256.digest("QUIC CHLO and server config signature\x00" + "\x20\x00\x00\x00" + Digest::SHA256.digest("CHLO") + "SCFG")'
			data := []byte("W\xA6\xFC\xDE\xC7\xD2>c\xE6\xB5\xF6\tq\x9E|<~1\xA33\x01\xCA=\x19\xBD\xC1\xE4\xB0\xBA\x9B\x16%")
			err = rsa.VerifyPSS(key.PrivateKey.(*rsa.PrivateKey).Public().(*rsa.PublicKey), crypto.SHA256, data, signature, &rsa.PSSOptions{SaltLength: 32})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("when using ECDSA", func() {
		var (
			key  crypto.Signer
			cert *tls.Certificate
		)

		BeforeEach(func() {
			var err error
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			cert = &tls.Certificate{PrivateKey: key}
		})

		It("gives valid signatures", func() {
			signature, err := signServerProof(cert, []byte{'C', 'H', 'L', 'O'}, []byte{'S', 'C', 'F', 'G'})
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
})
