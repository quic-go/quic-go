package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	_ "net/http/pprof"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/testdata"
	"github.com/lucas-clemente/quic-go/utils"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	// runtime.SetBlockProfileRate(1)

	verbose := flag.Bool("v", false, "verbose")
	bindTo := flag.String("bind", "localhost", "bind to")
	certPath := flag.String("certpath", "", "certificate directory")
	www := flag.String("www", "/var/www", "www data")
	flag.Parse()

	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}

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

	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Printf("error reading body while handling /echo: %s\n", err.Error())
		}
		w.Write(body)
	})
	http.Handle("/", http.FileServer(http.Dir(*www)))

	server, err := h2quic.NewServer(tlsConfig)
	if err != nil {
		panic(err)
	}

	// server.CloseAfterFirstRequest = true

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
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDer},
			PrivateKey:  key,
		}},
	}, nil
}
