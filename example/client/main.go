package main

import (
	"flag"
	"net/http"
	"sync"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/utils"
)

func main() {
	verbose := flag.Bool("v", false, "verbose")
	flag.Parse()
	urls := flag.Args()

	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}

	hclient := &http.Client{
		Transport: &h2quic.QuicRoundTripper{},
	}

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		utils.Infof("GET %s", addr)
		go func(addr string) {
			rsp, err := hclient.Get(addr)
			if err != nil {
				panic(err)
			}
			utils.Infof("Got response for %s: %#v", addr, rsp)
			wg.Done()
		}(addr)
	}
	wg.Wait()
}
