package pqc

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Signer interface for digital signature operations
type Signer interface {
	PublicKey() []byte
	Sign(message []byte) ([]byte, error)
	Verify(message, signature []byte) bool
	Algorithm() string
	SecurityLevel() int
}

// MLDSA44Signer implements ML-DSA-44 (128-bit security level)
type MLDSA44Signer struct {
	publicKey  mldsa44.PublicKey
	privateKey mldsa44.PrivateKey
}

// NewMLDSA44Signer creates a new ML-DSA-44 signer
func NewMLDSA44Signer() (*MLDSA44Signer, error) {
	pub, priv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA-44 keypair: %w", err)
	}

	return &MLDSA44Signer{
		publicKey:  *pub,
		privateKey: *priv,
	}, nil
}

// PublicKey returns the public key bytes
func (s *MLDSA44Signer) PublicKey() []byte {
	pubBytes, _ := s.publicKey.MarshalBinary()
	return pubBytes
}

// Sign creates a signature over the message
func (s *MLDSA44Signer) Sign(message []byte) ([]byte, error) {
	// Allocate signature buffer (ML-DSA-44 signatures are about 2420 bytes)
	signature := make([]byte, 2420)
	err := mldsa44.SignTo(&s.privateKey, message, nil, true, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return signature, nil
}

// Verify checks a signature over the message
func (s *MLDSA44Signer) Verify(message, signature []byte) bool {
	// Strict length validation per FIPS 204
	if len(signature) != 2420 {
		return false
	}
	return mldsa44.Verify(&s.publicKey, message, nil, signature)
}

// Algorithm returns the algorithm name
func (s *MLDSA44Signer) Algorithm() string {
	return "ML-DSA-44"
}

// SecurityLevel returns the security level in bits
func (s *MLDSA44Signer) SecurityLevel() int {
	return 44
}

// MLDSA65Signer implements ML-DSA-65 (192-bit security level) - RECOMMENDED
type MLDSA65Signer struct {
	publicKey  mldsa65.PublicKey
	privateKey mldsa65.PrivateKey
}

// NewMLDSA65Signer creates a new ML-DSA-65 signer (recommended for most applications)
func NewMLDSA65Signer() (*MLDSA65Signer, error) {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA-65 keypair: %w", err)
	}

	return &MLDSA65Signer{
		publicKey:  *pub,
		privateKey: *priv,
	}, nil
}

// PublicKey returns the public key bytes
func (s *MLDSA65Signer) PublicKey() []byte {
	pubBytes, _ := s.publicKey.MarshalBinary()
	return pubBytes
}

// Sign creates a signature over the message
func (s *MLDSA65Signer) Sign(message []byte) ([]byte, error) {
	// Allocate signature buffer (ML-DSA-65 signatures are about 3309 bytes)
	signature := make([]byte, 3309)
	err := mldsa65.SignTo(&s.privateKey, message, nil, true, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return signature, nil
}

// Verify checks a signature over the message
func (s *MLDSA65Signer) Verify(message, signature []byte) bool {
	// Strict length validation per FIPS 204
	if len(signature) != 3309 {
		return false
	}
	return mldsa65.Verify(&s.publicKey, message, nil, signature)
}

// Algorithm returns the algorithm name
func (s *MLDSA65Signer) Algorithm() string {
	return "ML-DSA-65"
}

// SecurityLevel returns the security level in bits
func (s *MLDSA65Signer) SecurityLevel() int {
	return 65
}

// MLDSA87Signer implements ML-DSA-87 (256-bit security level)
type MLDSA87Signer struct {
	publicKey  mldsa87.PublicKey
	privateKey mldsa87.PrivateKey
}

// NewMLDSA87Signer creates a new ML-DSA-87 signer (high security)
func NewMLDSA87Signer() (*MLDSA87Signer, error) {
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA-87 keypair: %w", err)
	}

	return &MLDSA87Signer{
		publicKey:  *pub,
		privateKey: *priv,
	}, nil
}

// PublicKey returns the public key bytes
func (s *MLDSA87Signer) PublicKey() []byte {
	pubBytes, _ := s.publicKey.MarshalBinary()
	return pubBytes
}

// Sign creates a signature over the message
func (s *MLDSA87Signer) Sign(message []byte) ([]byte, error) {
	// Allocate signature buffer (ML-DSA-87 signatures are about 4627 bytes)
	signature := make([]byte, 4627)
	err := mldsa87.SignTo(&s.privateKey, message, nil, true, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return signature, nil
}

// Verify checks a signature over the message
func (s *MLDSA87Signer) Verify(message, signature []byte) bool {
	// Strict length validation per FIPS 204
	if len(signature) != 4627 {
		return false
	}
	return mldsa87.Verify(&s.publicKey, message, nil, signature)
}

// Algorithm returns the algorithm name
func (s *MLDSA87Signer) Algorithm() string {
	return "ML-DSA-87"
}

// SecurityLevel returns the security level in bits
func (s *MLDSA87Signer) SecurityLevel() int {
	return 87
}

// NewMLDSASigner creates an ML-DSA signer based on security level
func NewMLDSASigner(level int) (Signer, error) {
	switch level {
	case 44:
		return NewMLDSA44Signer()
	case 65:
		return NewMLDSA65Signer()
	case 87:
		return NewMLDSA87Signer()
	default:
		return nil, fmt.Errorf("unsupported ML-DSA security level: %d (must be 44, 65, or 87)", level)
	}
}

// VerifyMLDSASignature verifies a signature using a public key
func VerifyMLDSASignature(publicKeyBytes, message, signature []byte, level int) (bool, error) {
	switch level {
	case 44:
		// Strict length validation per FIPS 204
		if len(signature) != 2420 {
			return false, nil
		}
		var pub mldsa44.PublicKey
		if err := pub.UnmarshalBinary(publicKeyBytes); err != nil {
			return false, fmt.Errorf("failed to unmarshal ML-DSA-44 public key: %w", err)
		}
		return mldsa44.Verify(&pub, message, nil, signature), nil

	case 65:
		// Strict length validation per FIPS 204
		if len(signature) != 3309 {
			return false, nil
		}
		var pub mldsa65.PublicKey
		if err := pub.UnmarshalBinary(publicKeyBytes); err != nil {
			return false, fmt.Errorf("failed to unmarshal ML-DSA-65 public key: %w", err)
		}
		return mldsa65.Verify(&pub, message, nil, signature), nil

	case 87:
		// Strict length validation per FIPS 204
		if len(signature) != 4627 {
			return false, nil
		}
		var pub mldsa87.PublicKey
		if err := pub.UnmarshalBinary(publicKeyBytes); err != nil {
			return false, fmt.Errorf("failed to unmarshal ML-DSA-87 public key: %w", err)
		}
		return mldsa87.Verify(&pub, message, nil, signature), nil

	default:
		return false, fmt.Errorf("unsupported ML-DSA security level: %d", level)
	}
}
