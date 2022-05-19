package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"runtime"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
)

var (
	caCertPath string
)

func init() {
	caCertPath = func() string {
		_, filename, _, ok := runtime.Caller(0)
		if !ok {
			panic("Failed to get current frame")
		}

		certPath := path.Dir(filename)
		return path.Join(certPath, "/testdata/ca.pem")
	}()
}

func main() {
	quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	flag.Parse()
	fmt.Println("Start http3 client")
	urls := flag.Args()
	if len(urls) == 0 {
		urls = append(urls, "https://localhost:6121")
	}

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
	caCertRaw, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		panic(err)
	}
	if ok := pool.AppendCertsFromPEM(caCertRaw); !ok {
		panic("Could not add root ceritificate to pool.")
	}

	var qconf quic.Config
	if *enableQlog {
		qconf.Tracer = qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			filename := fmt.Sprintf("client_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})
	}
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: *insecure,
			KeyLogWriter:       keyLog,
		},
		QuicConfig: &qconf,
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		fmt.Printf("GET %s", addr)
		go func(addr string) {
			rsp, err := hclient.Get(addr)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Got response for %s: %#v", addr, rsp)

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				log.Fatal(err)
			}
			if *quiet {
				fmt.Printf("Response Body: %d bytes", body.Len())
			} else {
				fmt.Printf("Response Body:")
				fmt.Printf("%s", body.Bytes())
			}
			wg.Done()
		}(addr)
	}
	wg.Wait()
}
