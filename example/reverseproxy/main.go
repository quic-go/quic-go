package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"

	_ "net/http/pprof"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type binds []string
const defaultBind = "localhost:6121"

func (b binds) String() string {
	return strings.Join(b, ",")
}

func (b *binds) Set(v string) error {
	*b = strings.Split(v, ",")
	return nil
}

// Size is needed by the /demo/upload handler to determine the size of the uploaded file
type Size interface {
	Size() int64
}

func getBuildDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("Failed to get current frame")
	}

	return path.Dir(filename)
}

func main() {
	verbose := flag.Bool("v", false, "verbose")
	bs := binds{}
	flag.Var(&bs, "bind", "bind to <address>:<port>,... (default \"" + defaultBind + "\")")
	certPath := flag.String("certpath", getBuildDir(), "certificate directory")
	tcp := flag.Bool("tcp", false, "also listen on TCP")
	tls := flag.Bool("tls", false, "activate support for IETF QUIC (work in progress)")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s backend_url\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		return
	}

	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}
	utils.SetLogTimeFormat("")

	versions := protocol.SupportedVersions
	if *tls {
		versions = append([]protocol.VersionNumber{protocol.VersionTLS}, versions...)
	}

	certFile := *certPath + "/fullchain.pem"
	keyFile := *certPath + "/privkey.pem"

	if len(bs) == 0 {
		bs = binds{defaultBind}
	}

	proxyUrl := flag.Arg(0)
	parsedUrl, err := url.Parse(proxyUrl)
	if err != nil {
		log.Fatal(err)
		return
	}
	http.Handle("/", httputil.NewSingleHostReverseProxy(parsedUrl))

	var wg sync.WaitGroup
	wg.Add(len(bs))
	for _, b := range bs {
		bCap := b
		go func() {
			var err error
			if *tcp {
				err = h2quic.ListenAndServe(bCap, certFile, keyFile, nil)
			} else {
				server := h2quic.Server{
					Server:	 &http.Server{Addr: bCap},
					QuicConfig: &quic.Config{Versions: versions},
				}
				err = server.ListenAndServeTLS(certFile, keyFile)
			}
			if err != nil {
				fmt.Println(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
