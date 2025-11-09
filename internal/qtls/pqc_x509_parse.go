// Copyright 2024 The quic-go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package qtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// ParseMLDSACertificate attempts to parse an ML-DSA certificate
// Returns the ML-DSA public key and parsed certificate info
func ParseMLDSACertificate(certBytes []byte) (*MLDSAPublicKey, *x509.Certificate, error) {
	// Try parsing with standard x509 first (might fail for ML-DSA)
	stdCert, stdErr := x509.ParseCertificate(certBytes)
	if stdErr == nil && !isMLDSACertificate(stdCert) {
		// It's a valid classical certificate, not ML-DSA
		return nil, stdCert, nil
	}

	// Parse as ML-DSA certificate
	var cert certificate
	rest, err := asn1.Unmarshal(certBytes, &cert)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("trailing data after certificate")
	}

	// Extract ML-DSA level from OID
	oid := cert.TBSCertificate.PublicKey.Algorithm.Algorithm
	var level int
	switch {
	case oid.Equal(oidMLDSA44):
		level = 44
	case oid.Equal(oidMLDSA65):
		level = 65
	case oid.Equal(oidMLDSA87):
		level = 87
	default:
		return nil, nil, fmt.Errorf("unknown ML-DSA OID: %v", oid)
	}

	// Extract public key bytes
	publicKeyBytes := cert.TBSCertificate.PublicKey.PublicKey.Bytes

	// Create ML-DSA public key
	mldsaPubKey := NewMLDSAPublicKey(publicKeyBytes, level)

	// Create a pseudo x509.Certificate for compatibility
	// This won't have all fields but enough for TLS to work
	pseudoCert := &x509.Certificate{
		Raw:                certBytes,
		RawTBSCertificate:  nil, // We'd need to marshal TBS separately
		RawSubjectPublicKeyInfo: nil,
		RawSubject:         nil,
		RawIssuer:          nil,

		Signature:          cert.SignatureValue.Bytes,
		SignatureAlgorithm: x509.UnknownSignatureAlgorithm,

		PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
		PublicKey:          mldsaPubKey,

		Version:      cert.TBSCertificate.Version + 1,
		SerialNumber: cert.TBSCertificate.SerialNumber,

		Issuer:  parseName(cert.TBSCertificate.Issuer),
		Subject: parseName(cert.TBSCertificate.Subject),

		NotBefore: cert.TBSCertificate.Validity.NotBefore,
		NotAfter:  cert.TBSCertificate.Validity.NotAfter,

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

		DNSNames:    extractDNSNames(cert.TBSCertificate.Extensions),
		IsCA:        false,
	}

	return mldsaPubKey, pseudoCert, nil
}

// isMLDSACertificate checks if a certificate uses ML-DSA
func isMLDSACertificate(cert *x509.Certificate) bool {
	// If parsing succeeded with x509, check if it's actually ML-DSA
	// (This won't happen in practice since x509 won't recognize ML-DSA OIDs)
	return cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm
}

// parseName converts an RDNSequence to a pkix.Name
func parseName(rdnSeq pkix.RDNSequence) pkix.Name {
	// This is a simplified parser - in production you'd want full parsing
	name := pkix.Name{}
	name.FillFromRDNSequence(&rdnSeq)
	return name
}

// extractDNSNames extracts DNS names from SAN extension
func extractDNSNames(extensions []asn1.RawValue) []string {
	for _, ext := range extensions {
		// Look for SAN extension (OID 2.5.29.17)
		var extension pkixExtension
		if _, err := asn1.Unmarshal(ext.FullBytes, &extension); err != nil {
			continue
		}

		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			var seq asn1.RawValue
			if _, err := asn1.Unmarshal(extension.Value, &seq); err != nil {
				continue
			}

			var dnsNames []string
			rest := seq.Bytes
			for len(rest) > 0 {
				var rawValue asn1.RawValue
				var err error
				rest, err = asn1.Unmarshal(rest, &rawValue)
				if err != nil {
					break
				}
				if rawValue.Tag == 2 { // dNSName
					dnsNames = append(dnsNames, string(rawValue.Bytes))
				}
			}
			return dnsNames
		}
	}
	return nil
}

// pkixExtension for parsing extensions
type pkixExtension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// VerifyMLDSACertificateSignature verifies the signature on an ML-DSA certificate
func VerifyMLDSACertificateSignature(certBytes []byte) error {
	var cert certificate
	if _, err := asn1.Unmarshal(certBytes, &cert); err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Marshal TBS certificate
	tbsBytes, err := asn1.Marshal(cert.TBSCertificate)
	if err != nil {
		return fmt.Errorf("failed to marshal TBS certificate: %w", err)
	}

	// Extract ML-DSA level
	oid := cert.TBSCertificate.PublicKey.Algorithm.Algorithm
	var level int
	switch {
	case oid.Equal(oidMLDSA44):
		level = 44
	case oid.Equal(oidMLDSA65):
		level = 65
	case oid.Equal(oidMLDSA87):
		level = 87
	default:
		return fmt.Errorf("unknown ML-DSA OID: %v", oid)
	}

	// Get public key
	publicKeyBytes := cert.TBSCertificate.PublicKey.PublicKey.Bytes
	mldsaPubKey := NewMLDSAPublicKey(publicKeyBytes, level)

	// Verify signature
	signature := cert.SignatureValue.Bytes
	return VerifyMLDSASignature(mldsaPubKey, tbsBytes, signature)
}

// IsMLDSACertificateBytes checks if certificate bytes contain an ML-DSA certificate
func IsMLDSACertificateBytes(certBytes []byte) bool {
	var cert certificate
	if _, err := asn1.Unmarshal(certBytes, &cert); err != nil {
		return false
	}

	oid := cert.TBSCertificate.PublicKey.Algorithm.Algorithm
	return oid.Equal(oidMLDSA44) || oid.Equal(oidMLDSA65) || oid.Equal(oidMLDSA87)
}
