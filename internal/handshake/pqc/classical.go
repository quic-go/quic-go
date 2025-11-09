package pqc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ClassicalProvider implements CryptoProvider for classical X25519
type ClassicalProvider struct{}

var _ CryptoProvider = &ClassicalProvider{}

func NewClassicalProvider() *ClassicalProvider {
	return &ClassicalProvider{}
}

func (p *ClassicalProvider) GenerateKeyPair() (KeyExchange, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 keypair: %w", err)
	}

	return &ClassicalKeyExchange{
		privateKey: privateKey,
		publicKey:  privateKey.PublicKey(),
	}, nil
}

func (p *ClassicalProvider) Mode() CryptoMode {
	return ModeClassical
}

func (p *ClassicalProvider) KeyExchangeAlgorithm() string {
	return "X25519"
}

func (p *ClassicalProvider) SignatureAlgorithm() string {
	return "ECDSA-P256"
}

func (p *ClassicalProvider) GenerateSigner() (Signer, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA keypair: %w", err)
	}

	return &ECDSASigner{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

func (p *ClassicalProvider) SecurityLevel() int {
	return 128 // X25519 provides ~128-bit security
}

// ClassicalKeyExchange implements KeyExchange for X25519
type ClassicalKeyExchange struct {
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
}

var _ KeyExchange = &ClassicalKeyExchange{}

func (k *ClassicalKeyExchange) PublicKey() []byte {
	return k.publicKey.Bytes()
}

func (k *ClassicalKeyExchange) DeriveSharedSecret(peerPublicKeyBytes []byte, isClient bool) ([]byte, error) {
	peerPublicKey, err := ecdh.X25519().NewPublicKey(peerPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer public key: %w", err)
	}

	sharedSecret, err := k.privateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	return sharedSecret, nil
}

// ECDSASigner implements Signer for ECDSA P-256
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

var _ Signer = &ECDSASigner{}

func (s *ECDSASigner) PublicKey() []byte {
	return elliptic.Marshal(s.publicKey.Curve, s.publicKey.X, s.publicKey.Y)
}

func (s *ECDSASigner) Sign(message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	r, sigS, err := ecdsa.Sign(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// Encode signature as concatenation of r and s
	signature := append(r.Bytes(), sigS.Bytes()...)
	return signature, nil
}

func (s *ECDSASigner) Verify(message, signature []byte) bool {
	if len(signature) < 64 {
		return false
	}

	hash := sha256.Sum256(message)
	r := new(big.Int).SetBytes(signature[:32])
	sigS := new(big.Int).SetBytes(signature[32:64])

	return ecdsa.Verify(s.publicKey, hash[:], r, sigS)
}

func (s *ECDSASigner) Algorithm() string {
	return "ECDSA-P256"
}

func (s *ECDSASigner) SecurityLevel() int {
	return 128
}
