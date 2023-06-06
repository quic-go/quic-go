package tools

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

const ALPN = "quic-go integration tests"

func GenerateCA() (*x509.Certificate, crypto.PrivateKey, error) {
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, certTempl, certTempl, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}
	return ca, priv, nil
}

func GenerateLeafCert(ca *x509.Certificate, caPriv crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	certTempl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTempl, ca, pub, caPriv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

// GenerateTLSConfigWithLongCertChain generates a tls.Config that uses a long certificate chain.
// The Root CA used is the same as for the config returned from getTLSConfig().
func GenerateTLSConfigWithLongCertChain(ca *x509.Certificate, caPrivateKey crypto.PrivateKey) (*tls.Config, error) {
	const chainLen = 7
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	lastCA := ca
	lastCAPrivKey := caPrivateKey
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	certs := make([]*x509.Certificate, chainLen)
	for i := 0; i < chainLen; i++ {
		caBytes, err := x509.CreateCertificate(rand.Reader, certTempl, lastCA, &privKey.PublicKey, lastCAPrivKey)
		if err != nil {
			return nil, err
		}
		ca, err := x509.ParseCertificate(caBytes)
		if err != nil {
			return nil, err
		}
		certs[i] = ca
		lastCA = ca
		lastCAPrivKey = privKey
	}
	leafCert, leafPrivateKey, err := GenerateLeafCert(lastCA, lastCAPrivKey)
	if err != nil {
		return nil, err
	}

	rawCerts := make([][]byte, chainLen+1)
	for i, cert := range certs {
		rawCerts[chainLen-i] = cert.Raw
	}
	rawCerts[0] = leafCert.Raw

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: rawCerts,
			PrivateKey:  leafPrivateKey,
		}},
		NextProtos: []string{ALPN},
	}, nil
}
