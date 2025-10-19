package tools

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

const ALPN = "quic-go integration tests"

// use a very long validity period to cover the synthetic clock used in synctest
var (
	notBefore = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

func GenerateCA() (*x509.Certificate, crypto.PrivateKey, error) {
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               pkix.Name{},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
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
		NotBefore:    notBefore,
		NotAfter:     notAfter,
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
	const chainLen = 16
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               pkix.Name{},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	lastCA := ca
	lastCAPrivKey := caPrivateKey
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	certs := make([]*x509.Certificate, chainLen)
	for i := range chainLen {
		caBytes, err := x509.CreateCertificate(rand.Reader, certTempl, lastCA, priv.Public(), lastCAPrivKey)
		if err != nil {
			return nil, err
		}
		ca, err := x509.ParseCertificate(caBytes)
		if err != nil {
			return nil, err
		}
		certs[i] = ca
		lastCA = ca
		lastCAPrivKey = priv
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
