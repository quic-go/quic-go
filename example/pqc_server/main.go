package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"

	"github.com/quic-go/quic-go"
)

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
		NextProtos:   []string{"pqc-test"},
	}
}

func main() {
	// Default to classical mode if no argument provided
	cryptoMode := "classical"
	if len(os.Args) > 1 {
		cryptoMode = os.Args[1]
	}

	// Determine security level (768 or 1024) if PQC mode
	securityLevel := 768
	if len(os.Args) > 2 && cryptoMode == "pqc" {
		fmt.Sscanf(os.Args[2], "%d", &securityLevel)
	}

	tlsConf := generateTLSConfig()

	config := &quic.Config{
		CryptoMode:       cryptoMode,
		PQCSecurityLevel: securityLevel,
	}

	log.Printf("Starting server with CryptoMode=%s, SecurityLevel=%d", cryptoMode, securityLevel)

	listener, err := quic.ListenAddr("localhost:4242", tlsConf, config)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	log.Println("Server listening on localhost:4242")

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Failed to accept: %v", err)
			continue
		}

		log.Printf("Accepted connection from %s", conn.RemoteAddr())

		go handleConnection(conn)
	}
}

func handleConnection(conn *quic.Conn) {
	defer conn.CloseWithError(0, "")

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			if err.Error() != "Application error 0x0 (local)" {
				log.Printf("Failed to accept stream: %v", err)
			}
			return
		}

		go handleStream(stream)
	}
}

func handleStream(stream *quic.Stream) {
	defer stream.Close()

	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("Failed to read: %v", err)
		return
	}

	log.Printf("Received: %s", string(buf[:n]))

	response := fmt.Sprintf("Echo: %s", string(buf[:n]))
	_, err = stream.Write([]byte(response))
	if err != nil {
		log.Printf("Failed to write: %v", err)
		return
	}

	log.Printf("Sent: %s", response)
}
