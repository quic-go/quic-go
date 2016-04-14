// Taken and modified to have tag size = 12
// from https://github.com/EncEve/crypto/blob/master/chacha/chachaPoly1305.go
// TODO: Check, make independent

package chacha20poly1305trunc12

// Use of this source code is governed by a license
// that can be found in the LICENSE file.

import (
	"crypto/cipher"
	"crypto/subtle"

	"github.com/EncEve/crypto"
	"github.com/EncEve/crypto/chacha"
	"github.com/EncEve/crypto/poly1305"
)

// The AEAD cipher ChaCha20-Poly1305
type aeadCipher struct {
	key [32]byte
}

// NewAEAD returns a cipher.AEAD implementing the
// ChaCha20-Poly1305 construction specified in
// RFC 7539. The key argument must be 256 bit
// (32 byte).
func NewAEAD(key []byte) (cipher.AEAD, error) {
	if k := len(key); k != 32 {
		return nil, crypto.KeySizeError(k)
	}
	c := new(aeadCipher)
	for i, v := range key {
		c.key[i] = v
	}
	return c, nil
}

func (c *aeadCipher) Overhead() int { return 12 }

func (c *aeadCipher) NonceSize() int { return chacha.NonceSize }

func (c *aeadCipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if n := len(nonce); n != chacha.NonceSize {
		panic(crypto.NonceSizeError(n))
	}
	if len(dst) < len(plaintext) {
		panic("dst buffer to small")
	}

	// create the ploy1305 key
	var polyKey [32]byte
	var tmp [64]byte
	chacha.XORKeyStream(tmp[:], c.key[:], nonce, 0, tmp[:])
	copy(polyKey[:], tmp[:32])

	// encrypt the plaintext
	n := len(plaintext)
	chacha.XORKeyStream(dst, c.key[:], nonce, 1, plaintext)

	// authenticate the ciphertext
	tag := authenticate(&polyKey, dst[:n], additionalData)
	return append(dst[:n], tag[0:12]...)
}

func (c *aeadCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if n := len(nonce); n != chacha.NonceSize {
		return nil, crypto.NonceSizeError(n)
	}
	if len(ciphertext) < 12 {
		return nil, crypto.AuthenticationError{}
	}
	if len(dst) < len(ciphertext)-12 {
		panic("dst buffer to small")
	}

	hash := ciphertext[len(ciphertext)-12:]
	ciphertext = ciphertext[:len(ciphertext)-12]

	// create the ploy1305 key
	var polyKey [32]byte
	var tmp [64]byte
	chacha.XORKeyStream(tmp[:], c.key[:], nonce, 0, tmp[:])
	copy(polyKey[:], tmp[:32])

	// authenticate the ciphertext
	tag := authenticate(&polyKey, ciphertext, additionalData)
	if subtle.ConstantTimeCompare(tag[0:12], hash[0:12]) != 1 {
		return nil, crypto.AuthenticationError{}
	}

	// decrypt ciphertext
	chacha.XORKeyStream(dst, c.key[:], nonce, 1, ciphertext)
	return dst[:len(ciphertext)], nil
}

// authenticate calculates the poly1305 tag from
// the given ciphertext and additional data.
func authenticate(key *[32]byte, ciphertext, additionalData []byte) []byte {
	ctLen := uint64(len(ciphertext))
	adLen := uint64(len(additionalData))
	padAD, padCT := adLen%16, ctLen%16

	var buf [16]byte
	buf[0] = byte(adLen)
	buf[1] = byte(adLen >> 8)
	buf[2] = byte(adLen >> 16)
	buf[3] = byte(adLen >> 24)
	buf[4] = byte(adLen >> 32)
	buf[5] = byte(adLen >> 40)
	buf[6] = byte(adLen >> 48)
	buf[7] = byte(adLen >> 56)
	buf[8] = byte(ctLen)
	buf[9] = byte(ctLen >> 8)
	buf[10] = byte(ctLen >> 16)
	buf[11] = byte(ctLen >> 24)
	buf[12] = byte(ctLen >> 32)
	buf[13] = byte(ctLen >> 40)
	buf[14] = byte(ctLen >> 48)
	buf[15] = byte(ctLen >> 56)

	poly, _ := poly1305.New(key[:])
	poly.Write(additionalData)
	if padAD > 0 {
		poly.Write(make([]byte, 16-padAD))
	}
	poly.Write(ciphertext)
	if padCT > 0 {
		poly.Write(make([]byte, 16-padCT))
	}
	poly.Write(buf[:])
	return poly.Sum(nil)
}
