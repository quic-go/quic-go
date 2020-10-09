package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/interop/http09"
	"github.com/lucas-clemente/quic-go/interop/utils"
	"github.com/lucas-clemente/quic-go/qlog"
)

var tlsConf *tls.Config

func main() {
	logFile, err := os.Create("/logs/log.txt")
	if err != nil {
		fmt.Printf("Could not create log file: %s\n", err.Error())
		os.Exit(1)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	keyLog, err := utils.GetSSLKeyLog()
	if err != nil {
		fmt.Printf("Could not create key log: %s\n", err.Error())
		os.Exit(1)
	}
	if keyLog != nil {
		defer keyLog.Close()
	}

	testcase := os.Getenv("TESTCASE")

	getLogWriter, err := utils.GetQLOGWriter()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	// a quic.Config that doesn't do a Retry
	quicConf := &quic.Config{
		AcceptToken: func(_ net.Addr, _ *quic.Token) bool { return true },
		Tracer:      qlog.NewTracer(getLogWriter),
	}
	cert, err := tls.LoadX509KeyPair("/certs/cert.pem", "/certs/priv.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	tlsConf = &tls.Config{
		Certificates: []tls.Certificate{cert},
		KeyLogWriter: keyLog,
	}

	switch testcase {
	case "versionnegotiation", "handshake", "transfer", "resumption", "zerortt", "multiconnect":
		err = runHTTP09Server(quicConf)
	case "chacha20":
		tlsConf.CipherSuites = []uint16{tls.TLS_CHACHA20_POLY1305_SHA256}
		err = runHTTP09Server(quicConf)
	case "retry":
		// By default, quic-go performs a Retry on every incoming connection.
		quicConf.AcceptToken = nil
		err = runHTTP09Server(quicConf)
	case "http3":
		err = runHTTP3Server(quicConf)
	default:
		fmt.Printf("unsupported test case: %s\n", testcase)
		os.Exit(127)
	}

	if err != nil {
		fmt.Printf("Error running server: %s\n", err.Error())
		os.Exit(1)
	}
}

func runHTTP09Server(quicConf *quic.Config) error {
	server := http09.Server{
		Server: &http.Server{
			Addr:      ":443",
			TLSConfig: tlsConf,
		},
		QuicConfig: quicConf,
	}
	http.DefaultServeMux.Handle("/", http.FileServer(http.Dir("/www")))
	return server.ListenAndServe()
}

func runHTTP3Server(quicConf *quic.Config) error {
	server := http3.Server{
		Server: &http.Server{
			Addr:      ":443",
			TLSConfig: tlsConf,
		},
		QuicConfig: quicConf,
	}
	http.DefaultServeMux.Handle("/", http.FileServer(http.Dir("/www")))
	return server.ListenAndServe()
}
