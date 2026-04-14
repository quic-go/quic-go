package pqc

import (
	"crypto/ed25519"
	"encoding/asn1"
	"fmt"
)

// HybridSigner implements Signer using a composite of Ed25519 + ML-DSA.
// Both signatures are required for verification (AND logic), providing
// security against both classical and quantum attacks.
type HybridSigner struct {
	ed25519Signer *Ed25519Signer
	mldsaSigner   Signer
	mldsaLevel    int
}

// compositeSignature is the ASN.1 encoding of a hybrid signature.
type compositeSignature struct {
	Ed25519Signature []byte
	MLDSASignature   []byte
}

// compositePublicKey is the ASN.1 encoding of a hybrid public key.
type compositePublicKey struct {
	Ed25519PublicKey []byte
	MLDSAPublicKey   []byte
}

// NewHybridSigner creates a new composite Ed25519 + ML-DSA signer.
func NewHybridSigner(mldsaLevel int) (*HybridSigner, error) {
	ed25519Signer, err := NewEd25519Signer()
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 signer: %w", err)
	}

	mldsaSigner, err := NewMLDSASigner(mldsaLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA signer: %w", err)
	}

	return &HybridSigner{
		ed25519Signer: ed25519Signer,
		mldsaSigner:   mldsaSigner,
		mldsaLevel:    mldsaLevel,
	}, nil
}

// NewHybridSignerFromComponents creates a HybridSigner from existing signers.
func NewHybridSignerFromComponents(ed25519Signer *Ed25519Signer, mldsaSigner Signer, mldsaLevel int) *HybridSigner {
	return &HybridSigner{
		ed25519Signer: ed25519Signer,
		mldsaSigner:   mldsaSigner,
		mldsaLevel:    mldsaLevel,
	}
}

func (s *HybridSigner) PublicKey() []byte {
	composite := compositePublicKey{
		Ed25519PublicKey: s.ed25519Signer.PublicKey(),
		MLDSAPublicKey:   s.mldsaSigner.PublicKey(),
	}
	encoded, err := asn1.Marshal(composite)
	if err != nil {
		return nil
	}
	return encoded
}

// Ed25519PublicKey returns the raw Ed25519 public key bytes.
func (s *HybridSigner) Ed25519PublicKey() []byte {
	return s.ed25519Signer.PublicKey()
}

// MLDSAPublicKey returns the raw ML-DSA public key bytes.
func (s *HybridSigner) MLDSAPublicKey() []byte {
	return s.mldsaSigner.PublicKey()
}

// Ed25519Signer returns the underlying Ed25519 signer.
func (s *HybridSigner) GetEd25519Signer() *Ed25519Signer {
	return s.ed25519Signer
}

// MLDSASigner returns the underlying ML-DSA signer.
func (s *HybridSigner) MLDSASigner() Signer {
	return s.mldsaSigner
}

// MLDSALevel returns the ML-DSA security level (44, 65, or 87).
func (s *HybridSigner) MLDSALevel() int {
	return s.mldsaLevel
}

func (s *HybridSigner) Sign(message []byte) ([]byte, error) {
	ed25519Sig, err := s.ed25519Signer.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("Ed25519 signing failed: %w", err)
	}

	mldsaSig, err := s.mldsaSigner.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA signing failed: %w", err)
	}

	composite := compositeSignature{
		Ed25519Signature: ed25519Sig,
		MLDSASignature:   mldsaSig,
	}
	encoded, err := asn1.Marshal(composite)
	if err != nil {
		return nil, fmt.Errorf("failed to encode composite signature: %w", err)
	}
	return encoded, nil
}

func (s *HybridSigner) Verify(message, signature []byte) bool {
	var composite compositeSignature
	rest, err := asn1.Unmarshal(signature, &composite)
	if err != nil || len(rest) > 0 {
		return false
	}

	if !s.ed25519Signer.Verify(message, composite.Ed25519Signature) {
		return false
	}
	if !s.mldsaSigner.Verify(message, composite.MLDSASignature) {
		return false
	}
	return true
}

func (s *HybridSigner) Algorithm() string {
	return fmt.Sprintf("Hybrid-Ed25519-ML-DSA-%d", s.mldsaLevel)
}

func (s *HybridSigner) SecurityLevel() int {
	return s.mldsaLevel
}

// ParseCompositePublicKey decodes a composite public key from ASN.1.
func ParseCompositePublicKey(data []byte) (ed25519Pub, mldsaPub []byte, err error) {
	var composite compositePublicKey
	rest, err := asn1.Unmarshal(data, &composite)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse composite public key: %w", err)
	}
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("trailing data after composite public key")
	}
	return composite.Ed25519PublicKey, composite.MLDSAPublicKey, nil
}

// ParseCompositeSignature decodes a composite signature from ASN.1.
func ParseCompositeSignature(data []byte) (ed25519Sig, mldsaSig []byte, err error) {
	var composite compositeSignature
	rest, err := asn1.Unmarshal(data, &composite)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse composite signature: %w", err)
	}
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("trailing data after composite signature")
	}
	return composite.Ed25519Signature, composite.MLDSASignature, nil
}

// VerifyHybridSignature verifies a composite signature against component public keys.
func VerifyHybridSignature(ed25519PubBytes, mldsaPubBytes, message, signature []byte, mldsaLevel int) (bool, error) {
	ed25519Sig, mldsaSig, err := ParseCompositeSignature(signature)
	if err != nil {
		return false, err
	}

	// Verify Ed25519 component
	if len(ed25519PubBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid Ed25519 public key length: %d", len(ed25519PubBytes))
	}
	if !ed25519.Verify(ed25519.PublicKey(ed25519PubBytes), message, ed25519Sig) {
		return false, nil
	}

	// Verify ML-DSA component
	ok, err := VerifyMLDSASignature(mldsaPubBytes, message, mldsaSig, mldsaLevel)
	if err != nil {
		return false, err
	}
	return ok, nil
}
