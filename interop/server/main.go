package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/internal/qtls"
	"github.com/quic-go/quic-go/interop/http09"
	"github.com/quic-go/quic-go/interop/utils"
)

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

	quicConf := &quic.Config{
		Allow0RTT: testcase == "zerortt",
		Tracer:    utils.NewQLOGConnectionTracer,
	}
	cert, err := tls.LoadX509KeyPair("/certs/cert.pem", "/certs/priv.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		KeyLogWriter: keyLog,
		NextProtos:   []string{http09.NextProto},
	}

	switch testcase {
	case "versionnegotiation", "handshake", "retry", "transfer", "resumption", "multiconnect", "zerortt":
		err = runHTTP09Server(tlsConf, quicConf, testcase == "retry")
	case "chacha20":
		reset := qtls.SetCipherSuite(tls.TLS_CHACHA20_POLY1305_SHA256)
		defer reset()
		err = runHTTP09Server(tlsConf, quicConf, false)
	case "http3":
		tlsConf.NextProtos = []string{http3.NextProtoH3}
		err = runHTTP3Server(tlsConf, quicConf)
	default:
		fmt.Printf("unsupported test case: %s\n", testcase)
		os.Exit(127)
	}

	if err != nil {
		fmt.Printf("Error running server: %s\n", err.Error())
		os.Exit(1)
	}
}

func runHTTP09Server(tlsConf *tls.Config, quicConf *quic.Config, forceRetry bool) error {
	http.DefaultServeMux.Handle("/", http.FileServer(http.Dir("/www")))
	server := http09.Server{}

	udpAddr, err := net.ResolveUDPAddr("udp", ":443")
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	tr := &quic.Transport{
		Conn:                conn,
		VerifySourceAddress: func(net.Addr) bool { return forceRetry },
	}
	ln, err := tr.ListenEarly(tlsConf, quicConf)
	if err != nil {
		return err
	}
	return server.ServeListener(ln)
}

func runHTTP3Server(tlsConf *tls.Config, quicConf *quic.Config) error {
	server := http3.Server{
		Addr:       ":443",
		TLSConfig:  tlsConf,
		QUICConfig: quicConf,
	}
	http.DefaultServeMux.Handle("/", http.FileServer(http.Dir("/www")))
	return server.ListenAndServe()
}
