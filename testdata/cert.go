package testdata

import (
	"crypto/tls"
	"os"
)

var certPath string

func init() {
	certPath = os.Getenv("GOPATH")
	certPath += "/src/github.com/lucas-clemente/quic-go/example"
}

// GetTLSConfig returns a tls config for quic.clemente.io
func GetTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(certPath+"/fullchain.pem", certPath+"/privkey.pem")
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

// GetCertificate returns a certificate for quic.clemente.io
func GetCertificate() tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certPath+"/fullchain.pem", certPath+"/privkey.pem")
	if err != nil {
		panic(err)
	}
	return cert
}
