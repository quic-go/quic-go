// Copyright (c) WithSecure Corporation
// https://foundry.withsecure.com
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

//go:build tamago
// +build tamago

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	_ "github.com/usbarmory/tamago/board/qemu/virt"
	"github.com/usbarmory/tamago/soc/nxp/imxrt1060"
)

// BenchmarkResult holds metrics for a single connection
type BenchmarkResult struct {
	Mode              string        `json:"mode"`                // "classic" or "pqc"
	HandshakeDuration time.Duration `json:"handshake_duration"`  // Time to complete handshake
	BytesTransferred  int64         `json:"bytes_transferred"`   // Total bytes sent
	TransferDuration  time.Duration `json:"transfer_duration"`   // Time to transfer data
	Throughput        float64       `json:"throughput_mbps"`     // Throughput in Mbps
	CipherSuite       uint16        `json:"cipher_suite"`        // TLS cipher suite
	CurveID           uint16        `json:"curve_id"`            // Key exchange algorithm
	Timestamp         time.Time     `json:"timestamp"`           // When test ran
}

var (
	testData = make([]byte, 1024*1024) // 1MB test data
)

func init() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// Initialize test data
	if _, err := rand.Read(testData); err != nil {
		log.Fatalf("Failed to generate test data: %v", err)
	}
}

func main() {
	log.Println("[SERVER] TamaGo QUIC PQC Benchmark Server starting...")

	// Generate test certificate
	cert, err := generateCertificate()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	// Read configuration from environment (set by QEMU)
	mode := getEnv("CRYPTO_MODE", "classic")
	securityLevel := 768
	if mode == "pqc" {
		securityLevel = 768 // ML-KEM-768
	}

	log.Printf("[SERVER] Mode: %s, SecurityLevel: %d", mode, securityLevel)

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"benchmark"},
	}

	// Configure QUIC
	quicConfig := &quic.Config{
		CryptoMode:       mode,
		PQCSecurityLevel: securityLevel,
		MaxIdleTimeout:   30 * time.Second,
	}

	// Listen on all interfaces
	listener, err := quic.ListenAddr("0.0.0.0:4433", tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	log.Println("[SERVER] Listening on 0.0.0.0:4433")

	// Accept connections
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("[SERVER] Accept error: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn quic.Connection) {
	defer conn.CloseWithError(0, "")

	startTime := time.Now()

	log.Printf("[SERVER] Connection accepted from %s", conn.RemoteAddr())

	// Get connection state
	connState := conn.ConnectionState()
	handshakeDuration := time.Since(startTime)

	// Accept stream
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("[SERVER] AcceptStream error: %v", err)
		return
	}
	defer stream.Close()

	transferStart := time.Now()
	var bytesTransferred int64

	// Send test data
	for i := 0; i < 10; i++ {
		n, err := stream.Write(testData)
		if err != nil {
			log.Printf("[SERVER] Write error: %v", err)
			return
		}
		bytesTransferred += int64(n)
	}

	transferDuration := time.Since(transferStart)
	throughputMbps := float64(bytesTransferred*8) / transferDuration.Seconds() / 1e6

	// Prepare result
	result := BenchmarkResult{
		Mode:              getEnv("CRYPTO_MODE", "classic"),
		HandshakeDuration: handshakeDuration,
		BytesTransferred:  bytesTransferred,
		TransferDuration:  transferDuration,
		Throughput:        throughputMbps,
		CipherSuite:       connState.TLS.CipherSuite,
		CurveID:           uint16(connState.TLS.CurveID),
		Timestamp:         time.Now(),
	}

	// Output result as JSON to stdout (will be captured by serial console)
	resultJSON, _ := json.Marshal(result)
	fmt.Printf("BENCHMARK_RESULT: %s\n", resultJSON)

	log.Printf("[SERVER] Completed: %d bytes in %v (%.2f Mbps)",
		bytesTransferred, transferDuration, throughputMbps)
}

func generateCertificate() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"QUIC PQC Benchmark"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("10.0.2.15")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Stub implementations for bare metal
func init() {
	if imxrt1060.Native {
		log.Println("Running on native TamaGo environment")
	}
}
