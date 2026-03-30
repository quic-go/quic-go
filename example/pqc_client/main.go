package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/quic-go/quic-go"
)

func main() {
	// Default to classical mode if no argument provided
	cryptoMode := "classical"
	if len(os.Args) > 1 {
		cryptoMode = os.Args[1]
	}

	// Determine security level (768 or 1024) for PQC/hybrid modes
	securityLevel := 768
	if len(os.Args) > 2 && (cryptoMode == "pqc" || cryptoMode == "hybrid") {
		fmt.Sscanf(os.Args[2], "%d", &securityLevel)
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"pqc-test"},
	}

	config := &quic.Config{
		CryptoMode:       cryptoMode,
		PQCSecurityLevel: securityLevel,
	}

	log.Printf("Connecting with CryptoMode=%s, SecurityLevel=%d", cryptoMode, securityLevel)

	conn, err := quic.DialAddr(context.Background(), "localhost:4242", tlsConf, config)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	log.Println("Connected successfully!")

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	// Send a message
	message := fmt.Sprintf("Hello from %s mode (security level %d)!", cryptoMode, securityLevel)
	_, err = stream.Write([]byte(message))
	if err != nil {
		log.Fatalf("Failed to write: %v", err)
	}

	log.Printf("Sent: %s", message)

	// Read response
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatalf("Failed to read: %v", err)
	}

	log.Printf("Received: %s", string(buf[:n]))
}
