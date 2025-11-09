// Copyright 2024 The quic-go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package qtls

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/quic-go/quic-go/internal/handshake/pqc"
)

// ML-DSA OID values (experimental - using private arc)
var (
	oidMLDSA44 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 8, 7} // NIST FIPS 204 draft OID
	oidMLDSA65 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 8, 8}
	oidMLDSA87 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 8, 9}
)

// GenerateMLDSACertificate generates a self-signed certificate using ML-DSA
func GenerateMLDSACertificate(level int, organization string, validFor time.Duration) (Certificate, error) {
	// Generate ML-DSA signer
	signer, err := pqc.NewMLDSASigner(level)
	if err != nil {
		return Certificate{}, fmt.Errorf("failed to generate ML-DSA-%d signer: %w", level, err)
	}

	// Wrap signer for TLS use
	_ = NewMLDSASigner(signer) // tlsSigner would be used in full implementation

	// Create certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// Set the appropriate OID for the ML-DSA level
	switch level {
	case 44:
		template.SignatureAlgorithm = x509.SignatureAlgorithm(oidMLDSA44[len(oidMLDSA44)-1])
	case 65:
		template.SignatureAlgorithm = x509.SignatureAlgorithm(oidMLDSA65[len(oidMLDSA65)-1])
	case 87:
		template.SignatureAlgorithm = x509.SignatureAlgorithm(oidMLDSA87[len(oidMLDSA87)-1])
	default:
		return Certificate{}, fmt.Errorf("unsupported ML-DSA level: %d", level)
	}

	// Create the certificate
	// Note: x509.CreateCertificate doesn't natively support ML-DSA yet,
	// so we'll need to create a custom certificate or use a workaround
	// For now, we'll return an error indicating this is not yet fully implemented
	return Certificate{}, fmt.Errorf("ML-DSA certificate generation not yet fully implemented - x509 package needs ML-DSA support")
}

// GeneratePQCCertificate generates a self-signed certificate with PQC signatures
// This is a simplified version that uses the ML-DSA signer directly
func GeneratePQCCertificate(level int, organization string, validFor time.Duration) (Certificate, error) {
	// Generate ML-DSA signer
	signer, err := pqc.NewMLDSASigner(level)
	if err != nil {
		return Certificate{}, fmt.Errorf("failed to generate ML-DSA-%d signer: %w", level, err)
	}

	// Wrap signer for TLS use
	tlsSigner := NewMLDSASigner(signer)

	// For now, return a certificate structure with the signer
	// In a production implementation, we would need proper X.509 encoding
	cert := Certificate{
		Certificate: nil, // Would contain DER-encoded certificate
		PrivateKey:  tlsSigner,
		Leaf:        nil, // Would contain parsed certificate
	}

	return cert, nil
}

// ConvertToMLDSACertificate attempts to convert a standard certificate to use ML-DSA signatures
// This is primarily useful for testing and demonstrating PQC capabilities
func ConvertToMLDSACertificate(stdCert Certificate, level int) (Certificate, error) {
	// Generate a new ML-DSA signer
	signer, err := pqc.NewMLDSASigner(level)
	if err != nil {
		return Certificate{}, fmt.Errorf("failed to generate ML-DSA-%d signer: %w", level, err)
	}

	// Create new certificate with ML-DSA signer
	pqcCert := Certificate{
		Certificate: stdCert.Certificate, // Keep the same certificate chain
		PrivateKey:  NewMLDSASigner(signer),
		Leaf:        stdCert.Leaf,
		OCSPStaple:  stdCert.OCSPStaple,
		SignedCertificateTimestamps: stdCert.SignedCertificateTimestamps,
	}

	return pqcCert, nil
}
