// Copyright 2024 The quic-go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package qtls

import (
	"crypto"
	"errors"
	"io"

	"github.com/quic-go/quic-go/internal/handshake/pqc"
)

// MLDSAPublicKey represents an ML-DSA public key for TLS certificate verification
type MLDSAPublicKey struct {
	publicKeyBytes []byte
	level          int // 44, 65, or 87
}

// NewMLDSAPublicKey creates a new ML-DSA public key wrapper
func NewMLDSAPublicKey(publicKeyBytes []byte, level int) *MLDSAPublicKey {
	return &MLDSAPublicKey{
		publicKeyBytes: publicKeyBytes,
		level:          level,
	}
}

// Bytes returns the raw public key bytes
func (pk *MLDSAPublicKey) Bytes() []byte {
	return pk.publicKeyBytes
}

// Level returns the ML-DSA security level (44, 65, or 87)
func (pk *MLDSAPublicKey) Level() int {
	return pk.level
}

// MLDSASigner wraps pqc.Signer to implement crypto.Signer interface
type MLDSASigner struct {
	signer pqc.Signer
}

// NewMLDSASigner creates a new ML-DSA signer from a PQC signer
func NewMLDSASigner(signer pqc.Signer) *MLDSASigner {
	return &MLDSASigner{signer: signer}
}

// Public returns the public key corresponding to the opaque,
// private key. This implements crypto.Signer interface.
func (s *MLDSASigner) Public() crypto.PublicKey {
	return NewMLDSAPublicKey(s.signer.PublicKey(), s.signer.SecurityLevel())
}

// Sign signs digest with the private key, possibly using entropy from
// rand. For ML-DSA, we ignore the digest parameter since ML-DSA
// signs the full message directly in TLS 1.3 context.
// This implements crypto.Signer interface.
func (s *MLDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// ML-DSA signs the full message, not a pre-hashed digest
	// The digest here is the full message prepared by TLS 1.3
	return s.signer.Sign(digest)
}

// Algorithm returns the ML-DSA algorithm name
func (s *MLDSASigner) Algorithm() string {
	return s.signer.Algorithm()
}

// SecurityLevel returns the security level in bits
func (s *MLDSASigner) SecurityLevel() int {
	return s.signer.SecurityLevel()
}

// VerifyMLDSASignature verifies an ML-DSA signature using the public key
func VerifyMLDSASignature(publicKey *MLDSAPublicKey, message, signature []byte) error {
	valid, err := pqc.VerifyMLDSASignature(publicKey.publicKeyBytes, message, signature, publicKey.level)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("ML-DSA signature verification failed")
	}
	return nil
}

// isMLDSAPublicKey checks if a public key is an ML-DSA public key
func isMLDSAPublicKey(pub crypto.PublicKey) bool {
	_, ok := pub.(*MLDSAPublicKey)
	return ok
}

// isMLDSASigner checks if a signer is an ML-DSA signer
func isMLDSASigner(signer crypto.Signer) bool {
	_, ok := signer.(*MLDSASigner)
	return ok
}
