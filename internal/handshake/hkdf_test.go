package handshake

import (
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

var tls13CipherSuites = []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256}

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

//go:linkname nextTrafficSecret crypto/tls.(*cipherSuiteTLS13).nextTrafficSecret
func nextTrafficSecret(cs *cipherSuiteTLS13, trafficSecret []byte) []byte

func TestHKDF(t *testing.T) {
	for _, id := range tls13CipherSuites {
		t.Run(tls.CipherSuiteName(id), func(t *testing.T) {
			cs := cipherSuiteTLS13ByID(id)
			expected := nextTrafficSecret(cs, []byte("foobar"))
			expanded := hkdfExpandLabel(cs.Hash, []byte("foobar"), nil, "traffic upd", cs.Hash.Size())
			require.Equal(t, expected, expanded)
		})
	}
}

// As of Go 1.24, the standard library and our implementation of hkdfExpandLabel should provide the same performance.
func BenchmarkHKDFExpandLabelStandardLibrary(b *testing.B) {
	for _, id := range tls13CipherSuites {
		b.Run(tls.CipherSuiteName(id), func(b *testing.B) { benchmarkHKDFExpandLabel(b, id, true) })
	}
}

func BenchmarkHKDFExpandLabelOurs(b *testing.B) {
	for _, id := range tls13CipherSuites {
		b.Run(tls.CipherSuiteName(id), func(b *testing.B) { benchmarkHKDFExpandLabel(b, id, false) })
	}
}

func benchmarkHKDFExpandLabel(b *testing.B, cipherSuite uint16, useStdLib bool) {
	b.ReportAllocs()
	cs := cipherSuiteTLS13ByID(cipherSuite)
	secret := make([]byte, 32)
	rand.Read(secret)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if useStdLib {
			nextTrafficSecret(cs, secret)
		} else {
			hkdfExpandLabel(cs.Hash, secret, nil, "traffic upd", cs.Hash.Size())
		}
	}
}
