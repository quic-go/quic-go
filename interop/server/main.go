package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/interop/http09"
)

func main() {
	logFile, err := os.Create("/logs/log.txt")
	if err != nil {
		fmt.Printf("Could not create log file: %s\n", err.Error())
		os.Exit(1)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	testcase := os.Getenv("TESTCASE")

	// a quic.Config that doesn't do a Retry
	quicConf := &quic.Config{
		AcceptToken: func(_ net.Addr, _ *quic.Token) bool { return true },
	}

	switch testcase {
	case "versionnegotiation", "handshake", "transfer", "resumption":
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
			Addr:      "0.0.0.0:443",
			TLSConfig: testdata.GetTLSConfig(),
		},
		QuicConfig: quicConf,
	}
	http.DefaultServeMux.Handle("/", http.FileServer(http.Dir("/www")))
	return server.ListenAndServe()
}

func runHTTP3Server(quicConf *quic.Config) error {
	server := http3.Server{
		Server: &http.Server{
			Addr:      "0.0.0.0:443",
			TLSConfig: testdata.GetTLSConfig(),
		},
		QuicConfig: quicConf,
	}
	http.DefaultServeMux.Handle("/", http.FileServer(http.Dir("/www")))
	return server.ListenAndServe()
}
