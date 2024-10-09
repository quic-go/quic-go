package handshake

import (
	"crypto"
	"crypto/cipher"
	"crypto/tls"
	"testing"
	"unsafe"

	"golang.org/x/exp/rand"

	"github.com/stretchr/testify/require"
)

type cipherSuiteTLS13 struct {
	ID     uint16
	KeyLen int
	AEAD   func(key, fixedNonce []byte) cipher.AEAD
	Hash   crypto.Hash
}

//go:linkname cipherSuitesTLS13 crypto/tls.cipherSuitesTLS13
var cipherSuitesTLS13 []unsafe.Pointer

func cipherSuiteTLS13ByID(id uint16) *cipherSuiteTLS13 {
	for _, v := range cipherSuitesTLS13 {
		cs := (*cipherSuiteTLS13)(v)
		if cs.ID == id {
			return cs
		}
	}
	return nil
}

//go:linkname expandLabel crypto/tls.(*cipherSuiteTLS13).expandLabel
func expandLabel(cs *cipherSuiteTLS13, secret []byte, label string, context []byte, length int) []byte

func TestHKDF(t *testing.T) {
	testCases := []struct {
		name        string
		cipherSuite uint16
		secret      []byte
		context     []byte
		label       string
		length      int
	}{
		{"TLS_AES_128_GCM_SHA256", tls.TLS_AES_128_GCM_SHA256, []byte("secret"), []byte("context"), "label", 42},
		{"TLS_AES_256_GCM_SHA384", tls.TLS_AES_256_GCM_SHA384, []byte("secret"), []byte("context"), "label", 100},
		{"TLS_CHACHA20_POLY1305_SHA256", tls.TLS_CHACHA20_POLY1305_SHA256, []byte("secret"), []byte("context"), "label", 77},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cs := cipherSuiteTLS13ByID(tc.cipherSuite)
			expected := expandLabel(cs, tc.secret, tc.label, tc.context, tc.length)
			expanded := hkdfExpandLabel(cs.Hash, tc.secret, tc.context, tc.label, tc.length)
			require.Equal(t, expected, expanded)
		})
	}
}

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
