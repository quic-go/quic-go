package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"

	_ "net/http/pprof"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/testdata"
	"github.com/lucas-clemente/quic-go/utils"
)

type binds []string

func (b binds) String() string {
	return strings.Join(b, ",")
}

func (b *binds) Set(v string) error {
	*b = strings.Split(v, ",")
	return nil
}

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	// runtime.SetBlockProfileRate(1)

	verbose := flag.Bool("v", false, "verbose")
	bs := binds{}
	flag.Var(&bs, "bind", "bind to")
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

	if len(bs) == 0 {
		bs = binds{"localhost:6121"}
	}

	var wg sync.WaitGroup
	wg.Add(len(bs))
	for _, b := range bs {
		bCap := b
		go func() {
			server := h2quic.Server{
				// CloseAfterFirstRequest: true,
				Server: &http.Server{
					Addr:      bCap,
					TLSConfig: tlsConfig,
				},
			}
			err := server.ListenAndServe()
			if err != nil {
				fmt.Println(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
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
