package pqc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// HybridSigner implements Signer using a composite of ECDSA-P256 + ML-DSA.
// Both signatures are required for verification (AND logic), providing
// security against both classical and quantum attacks.
type HybridSigner struct {
	ecdsaSigner *ECDSASigner
	mldsaSigner Signer
	mldsaLevel  int
}

// compositeSignature is the ASN.1 encoding of a hybrid signature.
type compositeSignature struct {
	ECDSASignature []byte
	MLDSASignature []byte
}

// compositePublicKey is the ASN.1 encoding of a hybrid public key.
type compositePublicKey struct {
	ECDSAPublicKey []byte
	MLDSAPublicKey []byte
}

// NewHybridSigner creates a new composite ECDSA-P256 + ML-DSA signer.
func NewHybridSigner(mldsaLevel int) (*HybridSigner, error) {
	classicalProvider := NewClassicalProvider()
	ecdsaSignerIface, err := classicalProvider.GenerateSigner()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA signer: %w", err)
	}
	ecdsaSigner, ok := ecdsaSignerIface.(*ECDSASigner)
	if !ok {
		return nil, fmt.Errorf("expected *ECDSASigner, got %T", ecdsaSignerIface)
	}

	mldsaSigner, err := NewMLDSASigner(mldsaLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA signer: %w", err)
	}

	return &HybridSigner{
		ecdsaSigner: ecdsaSigner,
		mldsaSigner: mldsaSigner,
		mldsaLevel:  mldsaLevel,
	}, nil
}

// NewHybridSignerFromComponents creates a HybridSigner from existing signers.
func NewHybridSignerFromComponents(ecdsaSigner *ECDSASigner, mldsaSigner Signer, mldsaLevel int) *HybridSigner {
	return &HybridSigner{
		ecdsaSigner: ecdsaSigner,
		mldsaSigner: mldsaSigner,
		mldsaLevel:  mldsaLevel,
	}
}

func (s *HybridSigner) PublicKey() []byte {
	composite := compositePublicKey{
		ECDSAPublicKey: s.ecdsaSigner.PublicKey(),
		MLDSAPublicKey: s.mldsaSigner.PublicKey(),
	}
	encoded, err := asn1.Marshal(composite)
	if err != nil {
		return nil
	}
	return encoded
}

// ECDSAPublicKey returns the raw ECDSA public key bytes.
func (s *HybridSigner) ECDSAPublicKey() []byte {
	return s.ecdsaSigner.PublicKey()
}

// MLDSAPublicKey returns the raw ML-DSA public key bytes.
func (s *HybridSigner) MLDSAPublicKey() []byte {
	return s.mldsaSigner.PublicKey()
}

// ECDSASigner returns the underlying ECDSA signer.
func (s *HybridSigner) ECDSASigner() *ECDSASigner {
	return s.ecdsaSigner
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
	ecdsaSig, err := s.ecdsaSigner.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	mldsaSig, err := s.mldsaSigner.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA signing failed: %w", err)
	}

	composite := compositeSignature{
		ECDSASignature: ecdsaSig,
		MLDSASignature: mldsaSig,
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

	if !s.ecdsaSigner.Verify(message, composite.ECDSASignature) {
		return false
	}
	if !s.mldsaSigner.Verify(message, composite.MLDSASignature) {
		return false
	}
	return true
}

func (s *HybridSigner) Algorithm() string {
	return fmt.Sprintf("Hybrid-ECDSA-P256-ML-DSA-%d", s.mldsaLevel)
}

func (s *HybridSigner) SecurityLevel() int {
	return s.mldsaLevel
}

// ParseCompositePublicKey decodes a composite public key from ASN.1.
func ParseCompositePublicKey(data []byte) (ecdsaPub, mldsaPub []byte, err error) {
	var composite compositePublicKey
	rest, err := asn1.Unmarshal(data, &composite)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse composite public key: %w", err)
	}
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("trailing data after composite public key")
	}
	return composite.ECDSAPublicKey, composite.MLDSAPublicKey, nil
}

// ParseCompositeSignature decodes a composite signature from ASN.1.
func ParseCompositeSignature(data []byte) (ecdsaSig, mldsaSig []byte, err error) {
	var composite compositeSignature
	rest, err := asn1.Unmarshal(data, &composite)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse composite signature: %w", err)
	}
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("trailing data after composite signature")
	}
	return composite.ECDSASignature, composite.MLDSASignature, nil
}

// VerifyHybridSignature verifies a composite signature against component public keys.
func VerifyHybridSignature(ecdsaPubBytes, mldsaPubBytes, message, signature []byte, mldsaLevel int) (bool, error) {
	ecdsaSig, mldsaSig, err := ParseCompositeSignature(signature)
	if err != nil {
		return false, err
	}

	// Verify ECDSA component
	x, y := elliptic.Unmarshal(elliptic.P256(), ecdsaPubBytes)
	if x == nil {
		return false, fmt.Errorf("failed to unmarshal ECDSA-P256 public key")
	}
	ecdsaPub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if len(ecdsaSig) < 64 {
		return false, nil
	}
	hash := sha256.Sum256(message)
	r := new(big.Int).SetBytes(ecdsaSig[:32])
	s := new(big.Int).SetBytes(ecdsaSig[32:64])
	if !ecdsa.Verify(ecdsaPub, hash[:], r, s) {
		return false, nil
	}

	// Verify ML-DSA component
	ok, err := VerifyMLDSASignature(mldsaPubBytes, message, mldsaSig, mldsaLevel)
	if err != nil {
		return false, err
	}
	return ok, nil
}
