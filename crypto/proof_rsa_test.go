package crypto

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ProofRsa", func() {
	It("gives correct cert", func() {
		cert := []byte{0xde, 0xca, 0xfb, 0xad}
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, certDictZlib)
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert)
		z.Close()
		kd := &KeyData{cert: &x509.Certificate{Raw: cert}}
		Expect(kd.GetCertCompressed()).To(Equal(append([]byte{
			0x01, 0x00,
			0x08, 0x00, 0x00, 0x00,
		}, certZlib.Bytes()...)))
	})

	It("gives valid signatures", func() {
		path := os.Getenv("GOPATH") + "/src/github.com/lucas-clemente/quic-go/example/"
		keyData, err := LoadKeyData(path+"cert.der", path+"key.der")
		Expect(err).ToNot(HaveOccurred())
		signature, err := keyData.SignServerProof([]byte{'C', 'H', 'L', 'O'}, []byte{'S', 'C', 'F', 'G'})
		Expect(err).ToNot(HaveOccurred())
		// Generated with:
		// ruby -e 'require "digest"; p Digest::SHA256.digest("QUIC CHLO and server config signature\x00" + "\x20\x00\x00\x00" + Digest::SHA256.digest("CHLO") + "SCFG")'
		data := []byte("W\xA6\xFC\xDE\xC7\xD2>c\xE6\xB5\xF6\tq\x9E|<~1\xA33\x01\xCA=\x19\xBD\xC1\xE4\xB0\xBA\x9B\x16%")
		err = rsa.VerifyPSS(keyData.cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, data, signature, &rsa.PSSOptions{SaltLength: 32})
		Expect(err).ToNot(HaveOccurred())
	})
})
