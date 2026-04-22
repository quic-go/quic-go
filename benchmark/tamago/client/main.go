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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	BytesReceived     int64         `json:"bytes_received"`      // Total bytes received
	TransferDuration  time.Duration `json:"transfer_duration"`   // Time to receive data
	Throughput        float64       `json:"throughput_mbps"`     // Throughput in Mbps
	CipherSuite       uint16        `json:"cipher_suite"`        // TLS cipher suite
	CurveID           uint16        `json:"curve_id"`            // Key exchange algorithm
	Timestamp         time.Time     `json:"timestamp"`           // When test ran
	Error             string        `json:"error,omitempty"`     // Error if any
}

func init() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
}

func main() {
	log.Println("[CLIENT] TamaGo QUIC PQC Benchmark Client starting...")

	// Read configuration from environment
	mode := getEnv("CRYPTO_MODE", "classic")
	serverAddr := getEnv("SERVER_ADDR", "10.0.2.15:4433")
	iterations := 10 // Run 10 iterations

	log.Printf("[CLIENT] Mode: %s, Server: %s, Iterations: %d", mode, serverAddr, iterations)

	// Run benchmark iterations
	for i := 0; i < iterations; i++ {
		log.Printf("[CLIENT] Starting iteration %d/%d", i+1, iterations)
		result := runBenchmark(mode, serverAddr)

		// Output result as JSON
		resultJSON, _ := json.Marshal(result)
		fmt.Printf("BENCHMARK_RESULT: %s\n", resultJSON)

		if result.Error != "" {
			log.Printf("[CLIENT] Iteration %d failed: %s", i+1, result.Error)
		} else {
			log.Printf("[CLIENT] Iteration %d: %.2f Mbps, handshake: %v",
				i+1, result.Throughput, result.HandshakeDuration)
		}

		// Brief delay between iterations
		time.Sleep(100 * time.Millisecond)
	}

	log.Println("[CLIENT] Benchmark completed")
}

func runBenchmark(mode, serverAddr string) BenchmarkResult {
	result := BenchmarkResult{
		Mode:      mode,
		Timestamp: time.Now(),
	}

	securityLevel := 768
	if mode == "pqc" {
		securityLevel = 768 // ML-KEM-768
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Skip verification for benchmark
		NextProtos:         []string{"benchmark"},
	}

	// Configure QUIC
	quicConfig := &quic.Config{
		CryptoMode:       mode,
		PQCSecurityLevel: securityLevel,
		MaxIdleTimeout:   30 * time.Second,
	}

	// Connect to server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialStart := time.Now()

	conn, err := quic.DialAddr(ctx, serverAddr, tlsConfig, quicConfig)
	if err != nil {
		result.Error = fmt.Sprintf("dial failed: %v", err)
		return result
	}
	defer conn.CloseWithError(0, "")

	result.HandshakeDuration = time.Since(dialStart)

	// Get connection state
	connState := conn.ConnectionState()
	result.CipherSuite = connState.TLS.CipherSuite
	result.CurveID = uint16(connState.TLS.CurveID)

	// Open stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("open stream failed: %v", err)
		return result
	}
	defer stream.Close()

	// Read data
	transferStart := time.Now()
	buf := make([]byte, 32*1024) // 32KB buffer
	var bytesReceived int64

	for {
		n, err := stream.Read(buf)
		bytesReceived += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			result.Error = fmt.Sprintf("read failed: %v", err)
			return result
		}
	}

	result.TransferDuration = time.Since(transferStart)
	result.BytesReceived = bytesReceived
	result.Throughput = float64(bytesReceived*8) / result.TransferDuration.Seconds() / 1e6

	return result
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
