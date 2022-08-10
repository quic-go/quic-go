package helper

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// NthBit gets the n-th bit of a byte (counting starts at 0).
func NthBit(val uint8, n int) bool {
	if n < 0 || n > 7 {
		panic("invalid value for n")
	}
	return val>>n&0x1 == 1
}

// WriteCorpusFile writes data to a corpus file in directory path.
// The filename is calculated from the SHA1 sum of the file contents.
func WriteCorpusFile(path string, data []byte) error {
	// create the directory, if it doesn't exist yet
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, os.ModePerm); err != nil {
			return err
		}
	}
	hash := sha1.Sum(data)
	return os.WriteFile(filepath.Join(path, hex.EncodeToString(hash[:])), data, 0o644)
}

// WriteCorpusFileWithPrefix writes data to a corpus file in directory path.
// In many fuzzers, the first n bytes are used to control.
// This function prepends n zero-bytes to the data.
func WriteCorpusFileWithPrefix(path string, data []byte, n int) error {
	return WriteCorpusFile(path, append(make([]byte, n), data...))
}

// GenerateCertificate generates a self-signed certificate.
// It returns the certificate and a x509.CertPool containing that certificate.
func GenerateCertificate(priv crypto.Signer) (*tls.Certificate, *x509.CertPool, error) {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"quic-go fuzzer"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, certPool, nil
}
