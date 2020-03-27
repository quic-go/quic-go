package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"log"
	"math/big"
)

func serverMain() {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		log.Fatalln(err)
	}
	defer listener.Close()
	for {
		s, err := listener.Accept(context.Background())
		if err != nil {
			log.Fatalln(err)
		}
		go handleSession(s)
	}
}

func handleSession(s quic.Session) {
	defer func() {
		s.CloseWithError(0, "OK")
		log.Println("Session closed", s.RemoteAddr())
	}()
	// set up custom congestion
	if !disableCustomCC {
		s.SetCongestion(NewBrutalSender(protocol.ByteCount(sendSpeed)))
	}
	// open stream
	stream, err := s.OpenStreamSync(context.Background())
	if err != nil {
		log.Println("Failed to open stream with", s.RemoteAddr(), err)
		return
	}
	log.Println("Stream opened successfully with", s.RemoteAddr())
	// send data
	buf := make([]byte, 4096)
	counter := 0
	for counter < dataSize {
		_, _ = rand.Read(buf)
		n, err := stream.Write(buf)
		if n > 0 {
			counter += n
		}
		if err != nil {
			log.Println("Failed to write", err)
			break
		}
	}
	log.Println(counter, "bytes written to", s.RemoteAddr())
	_ = stream.Close()
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{tlsProto},
	}
}
