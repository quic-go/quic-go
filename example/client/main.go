package main

import (
	"bytes"
	"crypto/x509"
	"flag"
	"github.com/Noooste/fhttp"
	"github.com/Noooste/utls"
	"io"
	"log"
	"os"
	"sync"

	"github.com/Noooste/quic-go"
	"github.com/Noooste/quic-go/http3"
	"github.com/Noooste/quic-go/internal/testdata"
	"github.com/Noooste/quic-go/qlog"
)

func main() {
	quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	flag.Parse()
	urls := flag.Args()

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	testdata.AddRootCA(pool)

	roundTripper := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: *insecure,
			KeyLogWriter:       keyLog,
		},
		QUICConfig: &quic.Config{
			Tracer: qlog.DefaultConnectionTracer,
		},
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		log.Printf("GET %s", addr)
		go func(addr string) {
			rsp, err := hclient.Get(addr)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Got response for %s: %#v", addr, rsp)

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				log.Fatal(err)
			}
			if *quiet {
				log.Printf("Response Body: %d bytes", body.Len())
			} else {
				log.Printf("Response Body (%d bytes):\n%s", body.Len(), body.Bytes())
			}
			wg.Done()
		}(addr)
	}
	wg.Wait()
}
