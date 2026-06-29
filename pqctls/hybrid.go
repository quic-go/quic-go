package pqctls

import (
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"time"
)

// compositeSigner is a crypto.Signer that produces composite Ed25519+ML-DSA
// signatures (an experimental, non-standard construction). It is used both as the
// TLS certificate private key and to self-sign the certificate.
type compositeSigner struct {
	ed    ed25519.PrivateKey
	mldsa *mldsa.PrivateKey
	pub   *x509.CompositePublicKey
}

func (s *compositeSigner) Public() crypto.PublicKey { return s.pub }

// Sign signs the (already-final) message with both component keys and returns the
// composite signature. The composite scheme uses direct signing (no pre-hash),
// so opts.HashFunc() is expected to be zero.
func (s *compositeSigner) Sign(rnd io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	edSig := ed25519.Sign(s.ed, message)
	mldsaSig, err := s.mldsa.Sign(rnd, message, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return x509.MarshalCompositeSignature(edSig, mldsaSig)
}

// GenerateHybridCertificate returns a self-signed certificate whose key and
// signature are a composite of Ed25519 and ML-DSA (at mldsaLevel 44, 65 or 87),
// so authentication holds as long as either scheme remains unbroken. This is an
// experimental, non-standard construction that requires the project's patched Go
// toolchain and interoperates only between peers using it.
func GenerateHybridCertificate(mldsaLevel int, organization string, dnsNames []string, validFor time.Duration) (tls.Certificate, error) {
	params, ok := mldsaParameters(mldsaLevel)
	if !ok {
		return tls.Certificate{}, &invalidLevelError{mldsaLevel}
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	mldsaPriv, err := mldsa.GenerateKey(params)
	if err != nil {
		return tls.Certificate{}, err
	}
	signer := &compositeSigner{
		ed:    edPriv,
		mldsa: mldsaPriv,
		pub: &x509.CompositePublicKey{
			Ed25519: edPub,
			MLDSA:   mldsaPriv.PublicKey(),
		},
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  signer,
		Leaf:        leaf,
	}, nil
}
