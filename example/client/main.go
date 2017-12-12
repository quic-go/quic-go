package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sync"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
)

// For additional logging of quic-go internals, the QUIC_GO_LOG_LEVEL env var
// can be set. See https://github.com/lucas-clemente/quic-go/wiki/Logging

func main() {
	tls := flag.Bool("tls", false, "activate support for IETF QUIC (work in progress)")
	flag.Parse()
	urls := flag.Args()

	versions := quic.SupportedVersions
	if *tls {
		versions = append([]quic.VersionNumber{quic.VersionTLS}, versions...)
	}

	hclient := &http.Client{
		Transport: &h2quic.RoundTripper{
			QuicConfig: &quic.Config{Versions: versions},
		},
	}

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		fmt.Printf("GET %s\n", addr)
		go func(addr string) {
			rsp, err := hclient.Get(addr)
			if err != nil {
				panic(err)
			}
			fmt.Printf("Got response for %s: %#v\n", addr, rsp)

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				panic(err)
			}
			fmt.Println("Request Body:")
			fmt.Printf("%s\n", body.Bytes())
			wg.Done()
		}(addr)
	}
	wg.Wait()
}
