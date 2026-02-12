package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// TokenProtectorKey is the key used to encrypt both Retry and session resumption tokens.
type TokenProtectorKey [32]byte

const tokenNonceSize = 32

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
	var nonce [tokenNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	aead, aeadNonce, err := s.createAEAD(nonce[:])
	if err != nil {
		return nil, err
	}
	return append(nonce[:], aead.Seal(nil, aeadNonce, data, nil)...), nil
}

// DecodeToken decodes a token.
func (s *tokenProtector) DecodeToken(p []byte) ([]byte, error) {
	if len(p) < tokenNonceSize {
		return nil, fmt.Errorf("token too short: %d", len(p))
	}
	nonce := p[:tokenNonceSize]
	aead, aeadNonce, err := s.createAEAD(nonce)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, aeadNonce, p[tokenNonceSize:], nil)
}

const tokenProtectorHKDFInfo = "quic-go token source"

func (s *tokenProtector) createAEAD(nonce []byte) (cipher.AEAD, []byte, error) {
	prk, err := hkdf.Extract(sha256.New, s.key[:], nonce)
	if err != nil {
		return nil, nil, err
	}

	// expand to get key (32 bytes) and nonce (12 bytes) in one HKDF call
	expanded, err := hkdf.Expand(sha256.New, prk, tokenProtectorHKDFInfo, 32+12)
	if err != nil {
		return nil, nil, err
	}

	key := expanded[:32] // use a 32 byte key, in order to select AES-256
	aeadNonce := expanded[32:]

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, nil, err
	}
	return aead, aeadNonce, nil
}
