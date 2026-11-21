package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// TokenProtectorKey is the key used to encrypt both Retry and session resumption tokens.
type TokenProtectorKey [32]byte

const tokenSaltSize = 32

// tokenProtector is used to create and verify a token
type tokenProtector struct {
	key TokenProtectorKey
}

// newTokenProtector creates a source for source address tokens
func newTokenProtector(key TokenProtectorKey) *tokenProtector {
	return &tokenProtector{key: key}
}

// NewToken encodes data into a new token.
func (s *tokenProtector) NewToken(data []byte) ([]byte, error) {
	var salt [tokenSaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	aead, err := s.createAEAD(salt[:])
	if err != nil {
		return nil, err
	}
	return aead.Seal(salt[:], nil, data, nil), nil
}

// DecodeToken decodes a token.
func (s *tokenProtector) DecodeToken(p []byte) ([]byte, error) {
	if len(p) < tokenSaltSize {
		return nil, fmt.Errorf("token too short: %d", len(p))
	}
	salt := p[:tokenSaltSize]
	aead, err := s.createAEAD(salt)
	if err != nil {
		return nil, err
	}
	if len(p[tokenSaltSize:]) < aead.Overhead() {
		return nil, fmt.Errorf("token too short: %d", len(p))
	}
	return aead.Open(nil, nil, p[tokenSaltSize:], nil)
}

const tokenProtectorHKDFInfo = "quic-go token source"

func (s *tokenProtector) createAEAD(salt []byte) (cipher.AEAD, error) {
	key, err := s.deriveKey(salt)
	if err != nil {
		return nil, err
	}
	c, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(c)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

// deriveKey derives the AEAD key using HKDF-Extract and HKDF-Expand (RFC 5869).
func (s *tokenProtector) deriveKey(salt []byte) ([32]byte, error) {
	var key [32]byte
	// In FIPS 140-3 mode, keys must be derived inside the module.
	if fips140.Enabled() {
		prk, err := hkdf.Extract(sha256.New, s.key[:], salt)
		if err != nil {
			return key, err
		}
		k, err := hkdf.Expand(sha256.New, prk, tokenProtectorHKDFInfo, len(key))
		if err != nil {
			return key, err
		}
		copy(key[:], k)
		return key, nil
	}
	// HKDF-Extract is HMAC(salt, IKM) (RFC 5869, Section 2.2). An HKDF-Expand output
	// of one hash length is the single block T(1) = HMAC(PRK, info || 0x01) (RFC 5869, Section 2.3).
	prk := hmacSHA256(salt, s.key[:])
	var info [len(tokenProtectorHKDFInfo) + 1]byte
	copy(info[:], tokenProtectorHKDFInfo)
	info[len(tokenProtectorHKDFInfo)] = 1
	return hmacSHA256(prk[:], info[:]), nil
}

// hmacSHA256 computes HMAC-SHA256 without heap allocations.
// HMAC(K, m) is H((K ^ opad) || H((K ^ ipad) || m)), with K zero-padded to the block size (RFC 2104, Section 2).
// The key must not be longer than the block size.
func hmacSHA256(key, msg []byte) [sha256.Size]byte {
	var in [sha256.BlockSize + 64]byte
	copy(in[:], key)
	for i := range sha256.BlockSize {
		in[i] ^= 0x36
	}
	inner := sha256.Sum256(append(in[:sha256.BlockSize], msg...))

	var out [sha256.BlockSize + sha256.Size]byte
	copy(out[:], key)
	for i := range sha256.BlockSize {
		out[i] ^= 0x5c
	}
	copy(out[sha256.BlockSize:], inner[:])
	return sha256.Sum256(out[:])
}
