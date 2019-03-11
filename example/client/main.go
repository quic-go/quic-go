package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"net/http"
	"sync"

	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

func main() {
	verbose := flag.Bool("v", false, "verbose")
	quiet := flag.Bool("q", false, "don't print the data")
	flag.Parse()
	urls := flag.Args()

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs: testdata.GetRootCA(),
		},
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		logger.Infof("GET %s", addr)
		go func(addr string) {
			rsp, err := hclient.Get(addr)
			if err != nil {
				panic(err)
			}
			logger.Infof("Got response for %s: %#v", addr, rsp)

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				panic(err)
			}
			if *quiet {
				logger.Infof("Request Body: %d bytes", body.Len())
			} else {
				logger.Infof("Request Body:")
				logger.Infof("%s", body.Bytes())
			}
			wg.Done()
		}(addr)
	}
	wg.Wait()
}
