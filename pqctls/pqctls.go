// Package pqctls exposes the post-quantum capabilities of Go's standard
// crypto/tls through helpers convenient for quic-go.
//
// Post-quantum behaviour is driven entirely by the *tls.Config passed to
// quic-go; there are no PQC-specific fields on quic.Config. Callers select:
//
//   - ML-KEM key exchange by listing a curve ID from this package in
//     tls.Config.CurvePreferences (e.g. pqctls.MLKEM768, pqctls.MLKEM1024 or the
//     hybrid pqctls.X25519MLKEM768);
//   - ML-DSA authentication by placing a certificate produced by
//     GenerateMLDSACertificate in tls.Config.Certificates.
//
// ML-KEM and ML-DSA are provided natively by the standard library
// (crypto/mlkem, crypto/mldsa, crypto/x509, crypto/tls). The pure ML-KEM-768
// curve (codepoint 513) and composite Ed25519+ML-DSA certificates require the
// project's patched Go toolchain; everything else builds on stock Go 1.27+.
package pqctls

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// Post-quantum key-exchange curve IDs, usable directly in
// tls.Config.CurvePreferences. Values match the standard crypto/tls CurveID
// numbering, so they interoperate with stdlib curve constants.
const (
	// X25519MLKEM768 is the hybrid X25519 + ML-KEM-768 key exchange (RFC-standard).
	X25519MLKEM768 tls.CurveID = 4588
	// MLKEM768 is pure ML-KEM-768 key exchange (codepoint 513; requires the
	// patched toolchain).
	MLKEM768 tls.CurveID = 513
	// MLKEM1024 is pure ML-KEM-1024 key exchange (codepoint 514).
	MLKEM1024 tls.CurveID = 514
)

// ML-DSA security levels accepted by GenerateMLDSACertificate and
// GenerateHybridCertificate.
const (
	MLDSA44 = 44 // ML-DSA-44 (NIST level 2)
	MLDSA65 = 65 // ML-DSA-65 (NIST level 3, recommended)
	MLDSA87 = 87 // ML-DSA-87 (NIST level 5)
)

// Composite Ed25519+ML-DSA TLS 1.3 signature schemes (experimental, non-standard
// private-use codepoints; require the patched toolchain). To use a composite
// certificate, the client must advertise the matching scheme by setting it in
// tls.Config.SignatureSchemes.
const (
	CompositeEd25519MLDSA44 tls.SignatureScheme = 0xFE10
	CompositeEd25519MLDSA65 tls.SignatureScheme = 0xFE11
	CompositeEd25519MLDSA87 tls.SignatureScheme = 0xFE12
)

// mldsaParameters maps a level (44/65/87) to the crypto/mldsa parameter set.
func mldsaParameters(level int) (mldsa.Parameters, bool) {
	switch level {
	case MLDSA44:
		return mldsa.MLDSA44(), true
	case MLDSA65:
		return mldsa.MLDSA65(), true
	case MLDSA87:
		return mldsa.MLDSA87(), true
	default:
		return mldsa.Parameters{}, false
	}
}

// GenerateMLDSACertificate returns a self-signed certificate whose key and
// signature use ML-DSA at the given level (44, 65 or 87), built with the native
// crypto/mldsa and crypto/x509 packages. The returned tls.Certificate can be
// placed directly into tls.Config.Certificates.
func GenerateMLDSACertificate(level int, organization string, dnsNames []string, validFor time.Duration) (tls.Certificate, error) {
	params, ok := mldsaParameters(level)
	if !ok {
		return tls.Certificate{}, &invalidLevelError{level}
	}
	priv, err := mldsa.GenerateKey(params)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{organization}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	// SignatureAlgorithm is left zero: x509.CreateCertificate derives the ML-DSA
	// algorithm from the signer's public key.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}, nil
}

type invalidLevelError struct{ level int }

func (e *invalidLevelError) Error() string {
	return "pqctls: invalid ML-DSA level (want 44, 65 or 87), got " + itoa(e.level)
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }
