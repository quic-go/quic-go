package handshake

import (
	"crypto"
	"crypto/cipher"
	"crypto/tls"
	"fmt"
	_ "unsafe"

	"golang.org/x/crypto/chacha20poly1305"
)

// These cipher suite implementations are copied from the standard library crypto/tls package.

const aeadNonceLength = 12

type cipherSuite struct {
	ID     uint16
	Hash   crypto.Hash
	KeyLen int
	AEAD   func(key, nonceMask []byte) cipher.AEAD
}

func (s cipherSuite) IVLen() int { return aeadNonceLength }

func getCipherSuite(id uint16) cipherSuite {
	switch id {
	case tls.TLS_AES_128_GCM_SHA256:
		return cipherSuite{ID: tls.TLS_AES_128_GCM_SHA256, Hash: crypto.SHA256, KeyLen: 16, AEAD: aeadAESGCMTLS13}
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return cipherSuite{ID: tls.TLS_CHACHA20_POLY1305_SHA256, Hash: crypto.SHA256, KeyLen: 32, AEAD: aeadChaCha20Poly1305}
	case tls.TLS_AES_256_GCM_SHA384:
		return cipherSuite{ID: tls.TLS_AES_256_GCM_SHA384, Hash: crypto.SHA384, KeyLen: 32, AEAD: aeadAESGCMTLS13}
	default:
		panic(fmt.Sprintf("unknown cypher suite: %d", id))
	}
}

//go:linkname cryptoTLSAEAD_AESGCMTLS13 crypto/tls.aeadAESGCMTLS13
func cryptoTLSAEAD_AESGCMTLS13(key, nonceMask []byte) cipher.AEAD

func aeadAESGCMTLS13(key, nonceMask []byte) cipher.AEAD {
	return &tls13AESGCMAEAD{aead: cryptoTLSAEAD_AESGCMTLS13(key, nonceMask)}
}

func aeadChaCha20Poly1305(key, nonceMask []byte) cipher.AEAD {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

type tls13AESGCMAEAD struct {
	aead       cipher.AEAD
	primedSeal bool
}

func (f *tls13AESGCMAEAD) NonceSize() int { return f.aead.NonceSize() }
func (f *tls13AESGCMAEAD) Overhead() int  { return f.aead.Overhead() }

func (f *tls13AESGCMAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	if !f.primedSeal {
		f.primedSeal = true
		if nonce[0]|nonce[1]|nonce[2]|nonce[3]|nonce[4]|nonce[5]|nonce[6]|nonce[7] != 0 {
			// Go's TLS 1.3 AES-GCM AEAD learns the XOR mask from the first Seal
			// call and enforces monotonically increasing packet numbers after that.
			// QUIC packet numbers don't reset on key updates, so prime it with
			// packet number 0 before the first real, non-zero packet number.
			var zeroNonce [8]byte
			f.aead.Seal(nil, zeroNonce[:], nil, nil)
		}
	}
	return f.aead.Seal(out, nonce, plaintext, additionalData)
}

func (f *tls13AESGCMAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return f.aead.Open(out, nonce, ciphertext, additionalData)
}

// xorNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int  { return f.aead.Overhead() }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result, err
}
