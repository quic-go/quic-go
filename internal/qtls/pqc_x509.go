// Copyright 2024 The quic-go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package qtls

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/quic-go/quic-go/internal/handshake/pqc"
)

// ML-DSA OIDs from NIST FIPS 204 (using draft OIDs)
// These are the official NIST OIDs for ML-DSA
var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17} // id-ml-dsa-44
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18} // id-ml-dsa-65
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19} // id-ml-dsa-87
)

// Composite hybrid OIDs (experimental, using private-use range)
// These represent ECDSA-P256 + ML-DSA composite certificates
var (
	oidCompositeECDSAP256MLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 32} // experimental
	oidCompositeECDSAP256MLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 33} // experimental
	oidCompositeECDSAP256MLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 34} // experimental
)

// ML-DSA public key sizes
const (
	mldsaPublicKeySize44 = 1312  // ML-DSA-44 public key bytes
	mldsaPublicKeySize65 = 1952  // ML-DSA-65 public key bytes
	mldsaPublicKeySize87 = 2592  // ML-DSA-87 public key bytes
)

// algorithmIdentifier represents an ASN.1 AlgorithmIdentifier
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// validity represents the validity period of a certificate
type validity struct {
	NotBefore time.Time `asn1:"utc"`
	NotAfter  time.Time `asn1:"utc"`
}

// subjectPublicKeyInfo represents an ASN.1 SubjectPublicKeyInfo
type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

// tbsCertificate represents the TBSCertificate structure
type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm algorithmIdentifier
	Issuer             pkix.RDNSequence
	Validity           validity
	Subject            pkix.RDNSequence
	PublicKey          subjectPublicKeyInfo
	Extensions         []asn1.RawValue `asn1:"optional,explicit,tag:3"`
}

// certificate represents an ASN.1 Certificate
type certificate struct {
	TBSCertificate     tbsCertificate
	SignatureAlgorithm algorithmIdentifier
	SignatureValue     asn1.BitString
}

// GenerateMLDSACertificate generates a self-signed certificate with ML-DSA
func GenerateMLDSACertificate(level int, organization string, dnsNames []string, validFor time.Duration) ([]byte, *MLDSASigner, error) {
	// Generate ML-DSA signer
	mldsaSigner, err := pqc.NewMLDSASigner(level)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ML-DSA-%d signer: %w", level, err)
	}

	// Wrap for TLS
	tlsSigner := NewMLDSASigner(mldsaSigner)

	// Get the OID for this ML-DSA level
	var oid asn1.ObjectIdentifier
	switch level {
	case 44:
		oid = oidMLDSA44
	case 65:
		oid = oidMLDSA65
	case 87:
		oid = oidMLDSA87
	default:
		return nil, nil, fmt.Errorf("unsupported ML-DSA level: %d", level)
	}

	// Generate serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create subject/issuer (self-signed)
	subject := pkix.Name{
		Organization: []string{organization},
		CommonName:   "QUIC-go ML-DSA Test Certificate",
	}
	subjectBytes, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal subject: %w", err)
	}
	var subjectSeq pkix.RDNSequence
	if _, err := asn1.Unmarshal(subjectBytes, &subjectSeq); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal subject: %w", err)
	}

	// Create validity
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	// Create extensions
	var extensions []asn1.RawValue

	// Add Subject Alternative Name (SAN) extension if DNS names provided
	if len(dnsNames) > 0 {
		sanExtension, err := createSANExtension(dnsNames)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create SAN extension: %w", err)
		}
		sanRaw, err := marshalExtension(sanExtension)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal SAN extension: %w", err)
		}
		extensions = append(extensions, sanRaw)
	}

	// Add Key Usage extension
	keyUsageExtension, err := createKeyUsageExtension()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key usage extension: %w", err)
	}
	keyUsageRaw, err := marshalExtension(keyUsageExtension)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal key usage extension: %w", err)
	}
	extensions = append(extensions, keyUsageRaw)

	// Add Extended Key Usage extension
	extKeyUsageExtension, err := createExtKeyUsageExtension()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create extended key usage extension: %w", err)
	}
	extKeyUsageRaw, err := marshalExtension(extKeyUsageExtension)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal extended key usage extension: %w", err)
	}
	extensions = append(extensions, extKeyUsageRaw)

	// Get ML-DSA public key
	publicKeyBytes := mldsaSigner.PublicKey()

	// Create SubjectPublicKeyInfo
	spki := subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.NullRawValue,
		},
		PublicKey: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: len(publicKeyBytes) * 8,
		},
	}

	// Create TBSCertificate
	tbs := tbsCertificate{
		Version:      2, // v3
		SerialNumber: serialNumber,
		SignatureAlgorithm: algorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.NullRawValue,
		},
		Issuer: subjectSeq,
		Validity: validity{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		},
		Subject:    subjectSeq,
		PublicKey:  spki,
		Extensions: extensions,
	}

	// Marshal TBSCertificate
	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal TBSCertificate: %w", err)
	}

	// Sign the TBSCertificate
	signature, err := mldsaSigner.Sign(tbsBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Create final certificate
	cert := certificate{
		TBSCertificate: tbs,
		SignatureAlgorithm: algorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.NullRawValue,
		},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	// Marshal final certificate
	certBytes, err := asn1.Marshal(cert)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal certificate: %w", err)
	}

	return certBytes, tlsSigner, nil
}

// createSANExtension creates a Subject Alternative Name extension
func createSANExtension(dnsNames []string) (pkix.Extension, error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   2, // dNSName tag
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(name),
		})
	}

	sanValue, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 17}, // id-ce-subjectAltName
		Critical: false,
		Value:    sanValue,
	}, nil
}

// createKeyUsageExtension creates a Key Usage extension
func createKeyUsageExtension() (pkix.Extension, error) {
	// digitalSignature (bit 0)
	keyUsage := 0x80 // 10000000 in binary

	keyUsageValue, err := asn1.Marshal(asn1.BitString{
		Bytes:     []byte{byte(keyUsage)},
		BitLength: 1,
	})
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // id-ce-keyUsage
		Critical: true,
		Value:    keyUsageValue,
	}, nil
}

// createExtKeyUsageExtension creates an Extended Key Usage extension
func createExtKeyUsageExtension() (pkix.Extension, error) {
	// serverAuth and clientAuth
	extKeyUsage := []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1}, // id-kp-serverAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 2}, // id-kp-clientAuth
	}

	extKeyUsageValue, err := asn1.Marshal(extKeyUsage)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37}, // id-ce-extKeyUsage
		Critical: false,
		Value:    extKeyUsageValue,
	}, nil
}

// marshalExtension converts a pkix.Extension to asn1.RawValue
func marshalExtension(ext pkix.Extension) (asn1.RawValue, error) {
	// Extension ::= SEQUENCE {
	//     extnID      OBJECT IDENTIFIER,
	//     critical    BOOLEAN DEFAULT FALSE,
	//     extnValue   OCTET STRING
	// }
	type extensionSeq struct {
		Id       asn1.ObjectIdentifier
		Critical bool   `asn1:"optional"`
		Value    []byte
	}

	extSeq := extensionSeq{
		Id:       ext.Id,
		Critical: ext.Critical,
		Value:    ext.Value,
	}

	extBytes, err := asn1.Marshal(extSeq)
	if err != nil {
		return asn1.RawValue{}, err
	}

	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(extBytes, &raw); err != nil {
		return asn1.RawValue{}, err
	}

	return raw, nil
}

// compositePublicKeyASN1 is the ASN.1 structure for a composite ECDSA + ML-DSA public key.
type compositePublicKeyASN1 struct {
	ECDSAPublicKey asn1.BitString
	MLDSAPublicKey asn1.BitString
}

// compositeSignatureASN1 is the ASN.1 structure for a composite ECDSA + ML-DSA signature.
type compositeSignatureASN1 struct {
	ECDSASignature asn1.BitString
	MLDSASignature asn1.BitString
}

// getCompositeOID returns the composite OID for the given ML-DSA level.
func getCompositeOID(mldsaLevel int) (asn1.ObjectIdentifier, error) {
	switch mldsaLevel {
	case 44:
		return oidCompositeECDSAP256MLDSA44, nil
	case 65:
		return oidCompositeECDSAP256MLDSA65, nil
	case 87:
		return oidCompositeECDSAP256MLDSA87, nil
	default:
		return nil, fmt.Errorf("unsupported ML-DSA level for hybrid: %d", mldsaLevel)
	}
}

// isCompositeOID checks if an OID is a composite hybrid OID and returns the ML-DSA level.
func isCompositeOID(oid asn1.ObjectIdentifier) (int, bool) {
	switch {
	case oid.Equal(oidCompositeECDSAP256MLDSA44):
		return 44, true
	case oid.Equal(oidCompositeECDSAP256MLDSA65):
		return 65, true
	case oid.Equal(oidCompositeECDSAP256MLDSA87):
		return 87, true
	default:
		return 0, false
	}
}

// GenerateHybridCertificate generates a self-signed certificate with composite
// ECDSA-P256 + ML-DSA signatures. Both keys are embedded in the certificate,
// and both algorithms sign the TBSCertificate.
func GenerateHybridCertificate(mldsaLevel int, organization string, dnsNames []string, validFor time.Duration) ([]byte, *HybridTLSSigner, error) {
	// Create hybrid signer (generates both ECDSA + ML-DSA keypairs)
	hybridPQCSigner, err := pqc.NewHybridSigner(mldsaLevel)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate hybrid signer: %w", err)
	}

	// Wrap for TLS
	tlsSigner := NewHybridTLSSigner(hybridPQCSigner)

	// Get composite OID
	oid, err := getCompositeOID(mldsaLevel)
	if err != nil {
		return nil, nil, err
	}

	// Generate serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create subject/issuer (self-signed)
	subject := pkix.Name{
		Organization: []string{organization},
		CommonName:   "QUIC-go Hybrid PQC Test Certificate",
	}
	subjectBytes, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal subject: %w", err)
	}
	var subjectSeq pkix.RDNSequence
	if _, err := asn1.Unmarshal(subjectBytes, &subjectSeq); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal subject: %w", err)
	}

	// Create validity
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	// Create extensions
	var extensions []asn1.RawValue

	if len(dnsNames) > 0 {
		sanExtension, err := createSANExtension(dnsNames)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create SAN extension: %w", err)
		}
		sanRaw, err := marshalExtension(sanExtension)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal SAN extension: %w", err)
		}
		extensions = append(extensions, sanRaw)
	}

	keyUsageExtension, err := createKeyUsageExtension()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key usage extension: %w", err)
	}
	keyUsageRaw, err := marshalExtension(keyUsageExtension)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal key usage extension: %w", err)
	}
	extensions = append(extensions, keyUsageRaw)

	extKeyUsageExtension, err := createExtKeyUsageExtension()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create extended key usage extension: %w", err)
	}
	extKeyUsageRaw, err := marshalExtension(extKeyUsageExtension)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal extended key usage extension: %w", err)
	}
	extensions = append(extensions, extKeyUsageRaw)

	// Create composite public key: ASN.1 SEQUENCE { ECDSA pub, ML-DSA pub }
	ecdsaPubBytes := hybridPQCSigner.ECDSAPublicKey()
	mldsaPubBytes := hybridPQCSigner.MLDSAPublicKey()

	compositeKey := compositePublicKeyASN1{
		ECDSAPublicKey: asn1.BitString{Bytes: ecdsaPubBytes, BitLength: len(ecdsaPubBytes) * 8},
		MLDSAPublicKey: asn1.BitString{Bytes: mldsaPubBytes, BitLength: len(mldsaPubBytes) * 8},
	}
	compositeKeyBytes, err := asn1.Marshal(compositeKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal composite public key: %w", err)
	}

	// Create SubjectPublicKeyInfo with composite OID
	spki := subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.NullRawValue,
		},
		PublicKey: asn1.BitString{
			Bytes:     compositeKeyBytes,
			BitLength: len(compositeKeyBytes) * 8,
		},
	}

	// Create TBSCertificate
	tbs := tbsCertificate{
		Version:      2, // v3
		SerialNumber: serialNumber,
		SignatureAlgorithm: algorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.NullRawValue,
		},
		Issuer: subjectSeq,
		Validity: validity{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		},
		Subject:    subjectSeq,
		PublicKey:  spki,
		Extensions: extensions,
	}

	// Marshal TBSCertificate
	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal TBSCertificate: %w", err)
	}

	// Sign with the composite signer (produces ASN.1 SEQUENCE of both signatures)
	compositeSig, err := hybridPQCSigner.Sign(tbsBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Create final certificate
	cert := certificate{
		TBSCertificate: tbs,
		SignatureAlgorithm: algorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.NullRawValue,
		},
		SignatureValue: asn1.BitString{
			Bytes:     compositeSig,
			BitLength: len(compositeSig) * 8,
		},
	}

	certBytes, err := asn1.Marshal(cert)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal certificate: %w", err)
	}

	return certBytes, tlsSigner, nil
}
