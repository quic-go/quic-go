package main

import (
	"bytes"
	"flag"
	"io"
	"net/http"
	"sync"
  "strings"
  "os"

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

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				panic(err)
			}
	//		utils.Infof("Request Body:")
	//		utils.Infof("%s", body.Bytes())
			fileName :=strings.Replace(rsp.Request.URL.Path, "/", "-", -1)
      dst, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0644)
      if err != nil {
        return
      }
      defer dst.Close()
      io.Copy(dst,body)
			wg.Done()
		}(addr)
	}
	wg.Wait()
}
