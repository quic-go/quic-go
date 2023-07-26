package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/quicvarint"
)

func main() {
	verbose := flag.Bool("v", false, "verbose")
	keyLogFile := flag.String("keylog", "", "key log file")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	proxyServer := flag.String("proxy", "https://127.0.0.1:8765", "Proxy server address")
	authToken := flag.String("authtoken", "", "Authorization token")
	certFile := flag.String("certfile", "", "Cert file to load")
	flag.Parse()
	urls := flag.Args()

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

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

	verifyPem := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error { return nil }
	if *certFile != "" {
		pemData, err := ioutil.ReadFile(*certFile)
		if err != nil {
			log.Fatal(err)
		}

		block, _ := pem.Decode([]byte(pemData))
		if block == nil {
			log.Fatal("failed to parse certificate PEM")
		}

		fastlyCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		pool.AddCert(fastlyCert)

		verifyPem = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) < 1 {
				return errors.New("didn't get any rawCerts")
			}
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil || fastlyCert.Equal(peerCert) {
				return nil
			}
			return errors.New("cert didn't matched pinned cert")
		}
	}

	qconf := quic.Config{
		EnableDatagrams:    true,
		MaxIncomingStreams: 100,
	}
	proxyUrl, err := url.ParseRequestURI(*proxyServer)
	if err != nil {
		log.Fatal(err)
	}

	if *enableQlog {
		qconf.Tracer = func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) logging.ConnectionTracer {
			filename := fmt.Sprintf("client_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return qlog.NewConnectionTracer(utils.NewBufferedWriteCloser(bufio.NewWriter(f), f), p, connID)
		}
	}
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:               pool,
			InsecureSkipVerify:    *insecure || (*certFile != ""),
			KeyLogWriter:          keyLog,
			VerifyPeerCertificate: verifyPem,
		},
		QuicConfig:      &qconf,
		Proxy:           http.ProxyURL(proxyUrl),
		EnableDatagrams: true,
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		logger.Infof("CONNECT-UDP %s", addr)
		go func(addr string) {
			fullAddr := fmt.Sprintf("masque://%s:443", addr)
			req, err := http.NewRequest("CONNECT-UDP", fullAddr, nil)

			// Assign a quarter stream ID (RFC 9297)
			flowID := 4
			sFlowID := strconv.Itoa(flowID)
			req.Header.Add("Datagram-Flow-Id", sFlowID)
			if *authToken != "" {
				req.Header.Add("Proxy-Authorization", fmt.Sprintf("PrivacyToken token=%s", *authToken))
			}
			if err != nil {
				log.Fatal(err)
			}

			rsp, err := hclient.Do(req)
			if err != nil {
				log.Fatal(err)
			}
			logger.Infof("Got response from %s: %#v", addr, rsp)
			if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
				log.Fatalf(rsp.Status)
			}

			hstr, e := rsp.Body.(http3.HTTPStreamer)
			if !e {
				log.Fatal("Failed to convert Streamer")
			}
			str := hstr.HTTPStream()
			conn := hstr.HTTPConnection()
			if conn == nil {
				log.Fatal("Failed to get connection object")
			}

			bbuf := &bytes.Buffer{}
			wbuf := quicvarint.NewWriter(bbuf)
			// Specify the flow ID before exchanging a message.
			i, _ := strconv.Atoi(sFlowID)
			b := byte(i)
			wbuf.WriteByte(b)
			wbuf.Write([]byte("Hello World from quic-go."))

			time.Sleep(time.Second / 2)

			err = conn.SendMessage(bbuf.Bytes())
			if err != nil {
				log.Fatal(err)
			}

			recv, err := conn.ReceiveMessage(context.Background())
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}

			logger.Infof("Received data:\n%s", string(recv))
			str.Close()

			wg.Done()
		}(addr)
	}
	wg.Wait()
}
