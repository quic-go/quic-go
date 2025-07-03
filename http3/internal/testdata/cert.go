package testdata

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path"
	"runtime"
)

var certPath string

func init() {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("Failed to get current frame")
	}

	certPath = path.Dir(filename)
}

// GetCertificatePaths returns the paths to certificate and key
func GetCertificatePaths() (string, string) {
	return path.Join(certPath, "cert.pem"), path.Join(certPath, "priv.key")
}

// GetTLSConfig returns a tls config for quic.clemente.io
func GetTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(GetCertificatePaths())
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
}

// AddRootCA adds the root CA certificate to a cert pool
func AddRootCA(certPool *x509.CertPool) {
	caCertPath := path.Join(certPath, "ca.pem")
	caCertRaw, err := os.ReadFile(caCertPath)
	if err != nil {
		panic(err)
	}
	if ok := certPool.AppendCertsFromPEM(caCertRaw); !ok {
		panic("Could not add root ceritificate to pool.")
	}
}

// GetRootCA returns an x509.CertPool containing (only) the CA certificate
func GetRootCA() *x509.CertPool {
	pool := x509.NewCertPool()
	AddRootCA(pool)
	return pool
}
