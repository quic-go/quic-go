package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"net/http"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/testdata"
	"github.com/lucas-clemente/quic-go/utils"
)

func main() {
	utils.SetLogLevel(utils.LogLevelDebug)

	bindTo := flag.String("bind", "localhost", "bind to")
	certPath := flag.String("certpath", "", "certificate directory")
	www := flag.String("www", "/var/www", "www data")
	flag.Parse()

	var tlsConfig *tls.Config
	if *certPath == "" {
		tlsConfig = testdata.GetTLSConfig()
	} else {
		var err error
		tlsConfig, err = tlsConfigFromCertpath(*certPath)
		if err != nil {
			panic(err)
		}
	}

	http.Handle("/", http.FileServer(http.Dir(*www)))

	server, err := h2quic.NewServer(tlsConfig)
	if err != nil {
		panic(err)
	}

	err = server.ListenAndServe(*bindTo+":6121", nil)
	if err != nil {
		panic(err)
	}
}

func tlsConfigFromCertpath(certpath string) (*tls.Config, error) {
	keyDer, err := ioutil.ReadFile(certpath + "/key.der")
	if err != nil {
		return nil, err
	}
	certDer, err := ioutil.ReadFile(certpath + "/cert.der")
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(keyDer)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{
			tls.Certificate{
				Certificate: [][]byte{certDer},
				PrivateKey:  key,
			},
		},
	}, nil
}
