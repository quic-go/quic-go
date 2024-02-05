package handshake

import (
	"crypto"
	"crypto/cipher"
	"crypto/tls"
	"testing"
	_ "unsafe"

	"golang.org/x/exp/rand"

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

func BenchmarkHKDFExpandLabelStandardLibrary(b *testing.B) {
	b.Run("TLS_AES_128_GCM_SHA256", func(b *testing.B) { benchmarkHKDFExpandLabel(b, tls.TLS_AES_128_GCM_SHA256, true) })
	b.Run("TLS_AES_256_GCM_SHA384", func(b *testing.B) { benchmarkHKDFExpandLabel(b, tls.TLS_AES_256_GCM_SHA384, true) })
	b.Run("TLS_CHACHA20_POLY1305_SHA256", func(b *testing.B) { benchmarkHKDFExpandLabel(b, tls.TLS_CHACHA20_POLY1305_SHA256, true) })
}

func BenchmarkHKDFExpandLabelOptimized(b *testing.B) {
	b.Run("TLS_AES_128_GCM_SHA256", func(b *testing.B) { benchmarkHKDFExpandLabel(b, tls.TLS_AES_128_GCM_SHA256, false) })
	b.Run("TLS_AES_256_GCM_SHA384", func(b *testing.B) { benchmarkHKDFExpandLabel(b, tls.TLS_AES_256_GCM_SHA384, false) })
	b.Run("TLS_CHACHA20_POLY1305_SHA256", func(b *testing.B) { benchmarkHKDFExpandLabel(b, tls.TLS_CHACHA20_POLY1305_SHA256, false) })
}

func benchmarkHKDFExpandLabel(b *testing.B, cipherSuite uint16, useStdLib bool) {
	b.ReportAllocs()
	cs := cipherSuiteTLS13ByID(cipherSuite)
	secret := make([]byte, 32)
	rand.Read(secret)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if useStdLib {
			expandLabel(cs, secret, "label", []byte("context"), 42)
		} else {
			hkdfExpandLabel(cs.Hash, secret, []byte("context"), "label", 42)
		}
	}
}
