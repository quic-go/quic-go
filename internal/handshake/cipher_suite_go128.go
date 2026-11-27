//go:build go1.28

package handshake

import (
	"crypto/aead"
	"crypto/aead/aesgcm"
	"crypto/aead/chacha20poly1305"
	"crypto/cipher"
	"slices"
)

func aeadAESGCMTLS13(key, nonceMask []byte) cipher.AEAD {
	a, err := aesgcm.NewWithXORCounterNonces(key, nonceMask)
	if err != nil {
		panic(err)
	}
	return newXORNonceAEAD(a, nonceMask)
}

func aeadChaCha20Poly1305(key, nonceMask []byte) cipher.AEAD {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return newXORNonceAEAD(a, nonceMask)
}

// xorNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      aead.AEAD
	sealed    bool
}

var _ cipher.AEAD = &xorNonceAEAD{}

func newXORNonceAEAD(a aead.AEAD, nonceMask []byte) *xorNonceAEAD {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	f := &xorNonceAEAD{aead: a}
	copy(f.nonceMask[:], nonceMask)
	return f
}

func (f *xorNonceAEAD) NonceSize() int { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int  { return f.aead.TagSize() }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	if !f.sealed {
		f.sealed = true
		// FIPS 140-3 module v1.0.0 requires the first sealed counter to be 0,
		// but QUIC packet numbers don't reset on key updates.
		if [8]byte(nonce) != [8]byte{} {
			var zero [8]byte
			f.Seal(nil, zero[:], nil, nil)
		}
	}
	tagSize := f.aead.TagSize()
	ret := slices.Grow(out, len(plaintext)+tagSize)[:len(out)+len(plaintext)+tagSize]
	dst := ret[len(out):]
	f.xorNonce(nonce)
	err := f.aead.SealRaw(dst[:len(plaintext)], dst[len(plaintext):], f.nonceMask[:], plaintext, additionalData)
	f.xorNonce(nonce)
	if err != nil {
		panic(err)
	}
	return ret
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	n := len(ciphertext) - f.aead.TagSize()
	if n < 0 {
		return nil, ErrDecryptionFailed
	}
	ret := slices.Grow(out, n)[:len(out)+n]
	f.xorNonce(nonce)
	err := f.aead.OpenRaw(ret[len(out):], f.nonceMask[:], ciphertext[:n], ciphertext[n:], additionalData)
	f.xorNonce(nonce)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (f *xorNonceAEAD) xorNonce(nonce []byte) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
}
