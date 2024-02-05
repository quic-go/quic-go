package handshake

import (
	"crypto"
	"crypto/cipher"
	"crypto/tls"
	_ "unsafe"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type cipherSuiteTLS13 struct {
	ID     uint16
	KeyLen int
	AEAD   func(key, fixedNonce []byte) cipher.AEAD
	Hash   crypto.Hash
}

//go:linkname cipherSuiteTLS13ByID crypto/tls.cipherSuiteTLS13ByID
func cipherSuiteTLS13ByID(id uint16) *cipherSuiteTLS13

//go:linkname expandLabel crypto/tls.(*cipherSuiteTLS13).expandLabel
func expandLabel(cs *cipherSuiteTLS13, secret []byte, label string, context []byte, length int) []byte

var _ = Describe("HKDF", func() {
	DescribeTable("gets the same results as crypto/tls",
		func(cipherSuite uint16, secret, context []byte, label string, length int) {
			cs := cipherSuiteTLS13ByID(cipherSuite)
			expected := expandLabel(cs, secret, label, context, length)
			expanded := hkdfExpandLabel(cs.Hash, secret, context, label, length)
			Expect(expanded).To(Equal(expected))
		},
		Entry("TLS_AES_128_GCM_SHA256", tls.TLS_AES_128_GCM_SHA256, []byte("secret"), []byte("context"), "label", 42),
		Entry("TLS_AES_256_GCM_SHA384", tls.TLS_AES_256_GCM_SHA384, []byte("secret"), []byte("context"), "label", 100),
		Entry("TLS_CHACHA20_POLY1305_SHA256", tls.TLS_CHACHA20_POLY1305_SHA256, []byte("secret"), []byte("context"), "label", 77),
	)
})
