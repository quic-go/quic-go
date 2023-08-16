//go:build utls

package testdata

import (
	"gitlab.com/go-extension/tls"
)

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
