package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

// BenchmarkResult holds metrics for a single connection
type BenchmarkResult struct {
	// Basic Info
	Mode              string        `json:"mode"`
	Iteration         int           `json:"iteration"`
	Timestamp         string        `json:"timestamp"`
	Error             string        `json:"error,omitempty"`

	// PQC Security Levels
	MLKEMLevel        int           `json:"mlkem_level"`         // 512, 768, 1024, or 0 for classical
	MLDSALevel        int           `json:"mldsa_level"`         // 44, 65, 87, or 0 for classical

	// A. Connection Establishment
	HandshakeDuration  time.Duration `json:"handshake_duration_ns"`
	PacketsSent        uint64        `json:"packets_sent"`
	PacketsReceived    uint64        `json:"packets_received"`
	HandshakeBytesSent uint64        `json:"handshake_bytes_sent"`
	HandshakeBytesRecv uint64        `json:"handshake_bytes_recv"`
	TimeToFirstByte    time.Duration `json:"time_to_first_byte_ns"`

	// B. Loss Recovery & Reliability
	RTTMin            time.Duration `json:"rtt_min_ns"`
	RTTSmoothed       time.Duration `json:"rtt_smoothed_ns"`
	RTTLatest         time.Duration `json:"rtt_latest_ns"`
	PacketsLost       uint64        `json:"packets_lost"`

	// C. Flow & Congestion Control
	CongestionWindow  uint64        `json:"congestion_window_bytes"`
	BytesInFlight     uint64        `json:"bytes_in_flight"`

	// D. Data Transfer
	BytesReceived     int64         `json:"bytes_received"`
	TransferDuration  time.Duration `json:"transfer_duration_ns"`
	TotalDuration     time.Duration `json:"total_duration_ns"`
	Throughput        float64       `json:"throughput_mbps"`

	// E. Crypto Info (minimal)
	CipherSuite       string        `json:"cipher_suite"`
	CurveID           string        `json:"curve_id"`
	CertChainSize     int           `json:"cert_chain_size_bytes"`

	// F. Resource Usage
	StreamsCreated    uint64        `json:"streams_created"`
}

var (
	serverAddr    = flag.String("server", "192.168.100.2:4433", "Server address")
	mode          = flag.String("mode", "classical", "Crypto mode: classical, pqc, or hybrid")
	securityLevel = flag.Int("security", 768, "PQC security level: 768 or 1024")
	iterations    = flag.Int("iterations", 10, "Number of iterations to run")
	timeout       = flag.Duration("timeout", 30*time.Second, "Connection timeout")
)

func main() {
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Printf("[CLIENT] Starting QUIC benchmark client")
	log.Printf("[CLIENT] Server: %s, Mode: %s, SecurityLevel: %d, Iterations: %d",
		*serverAddr, *mode, *securityLevel, *iterations)

	// Run benchmark iterations
	for i := 0; i < *iterations; i++ {
		log.Printf("[CLIENT] Running iteration %d/%d", i+1, *iterations)

		result := runBenchmark(i + 1)

		// Output result as JSON
		resultJSON, _ := json.Marshal(result)
		fmt.Printf("BENCHMARK_RESULT: %s\n", resultJSON)

		if result.Error != "" {
			log.Printf("[CLIENT] Iteration %d FAILED: %s", i+1, result.Error)
		} else {
			log.Printf("[CLIENT] Iteration %d: %.2f Mbps (handshake: %v, transfer: %v, total: %v)",
				i+1, result.Throughput, result.HandshakeDuration, result.TransferDuration, result.TotalDuration)
		}

		// Brief delay between iterations to ensure cleanup
		time.Sleep(1 * time.Second)
	}

	log.Println("[CLIENT] Benchmark completed")
}

func runBenchmark(iteration int) BenchmarkResult {
	result := BenchmarkResult{
		Mode:      *mode,
		Iteration: iteration,
		Timestamp: time.Now().Format(time.RFC3339Nano),
	}

	// Map security level to ML-KEM and ML-DSA levels
	result.MLKEMLevel, result.MLDSALevel = mapSecurityLevels(*mode, *securityLevel)

	totalStart := time.Now()

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Skip verification for benchmark
		NextProtos:         []string{"benchmark"},
	}

	// Configure QUIC
	quicConfig := &quic.Config{
		CryptoMode:       *mode,
		PQCSecurityLevel: *securityLevel,
		MaxIdleTimeout:   30 * time.Second,
	}

	// Connect to server - handshake happens here
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	log.Printf("[CLIENT] Connecting to %s...", *serverAddr)
	dialStart := time.Now()

	conn, err := quic.DialAddr(ctx, *serverAddr, tlsConfig, quicConfig)
	if err != nil {
		result.Error = fmt.Sprintf("dial failed: %v", err)
		result.TotalDuration = time.Since(totalStart)
		return result
	}
	defer conn.CloseWithError(0, "")

	// Handshake is complete when DialAddr returns successfully
	result.HandshakeDuration = time.Since(dialStart)
	log.Printf("[CLIENT] Connection established, handshake took %v", result.HandshakeDuration)

	// Get connection state and statistics
	connState := conn.ConnectionState()
	result.CipherSuite = fmt.Sprintf("0x%04x", connState.TLS.CipherSuite)
	result.CurveID = fmt.Sprintf("0x%04x", uint16(connState.TLS.CurveID))

	// Collect connection statistics (after handshake)
	stats := conn.ConnectionStats()
	result.PacketsSent = stats.PacketsSent
	result.PacketsReceived = stats.PacketsReceived
	result.PacketsLost = stats.PacketsLost
	result.HandshakeBytesSent = stats.BytesSent
	result.HandshakeBytesRecv = stats.BytesReceived

	// Get RTT statistics
	result.RTTMin = stats.MinRTT
	result.RTTSmoothed = stats.SmoothedRTT
	result.RTTLatest = stats.LatestRTT

	// Get certificate chain size
	if len(connState.TLS.PeerCertificates) > 0 {
		for _, cert := range connState.TLS.PeerCertificates {
			result.CertChainSize += len(cert.Raw)
		}
	}

	// Mark that we've created one stream
	result.StreamsCreated = 1

	// Open stream immediately
	log.Printf("[CLIENT] Opening stream...")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("open stream failed: %v", err)
		result.TotalDuration = time.Since(totalStart)
		return result
	}
	defer stream.Close()

	log.Printf("[CLIENT] Stream opened, starting data transfer")

	// Send a small "ready" byte to signal we're ready to receive
	// This ensures the stream is established on the server side
	_, err = stream.Write([]byte{0x01})
	if err != nil {
		result.Error = fmt.Sprintf("write ready signal failed: %v", err)
		result.TotalDuration = time.Since(totalStart)
		return result
	}

	log.Printf("[CLIENT] Sent ready signal, waiting for data")

	// Read data
	transferStart := time.Now()
	buf := make([]byte, 64*1024) // 64KB buffer
	var bytesReceived int64
	firstByteReceived := false

	for {
		n, err := stream.Read(buf)
		bytesReceived += int64(n)

		// Capture time to first byte
		if !firstByteReceived && n > 0 {
			result.TimeToFirstByte = time.Since(totalStart)
			firstByteReceived = true
		}

		if err == io.EOF {
			log.Printf("[CLIENT] Received EOF after %d bytes", bytesReceived)
			break
		}
		if err != nil {
			result.Error = fmt.Sprintf("read failed after %d bytes: %v", bytesReceived, err)
			result.TotalDuration = time.Since(totalStart)
			return result
		}
		// Log progress periodically
		if bytesReceived%(1024*1024) == 0 {
			log.Printf("[CLIENT] Received %d bytes...", bytesReceived)
		}
	}

	result.TransferDuration = time.Since(transferStart)
	result.BytesReceived = bytesReceived
	result.TotalDuration = time.Since(totalStart)

	if result.TransferDuration > 0 {
		result.Throughput = float64(bytesReceived*8) / result.TransferDuration.Seconds() / 1e6
	}

	// Collect final connection statistics (after data transfer)
	finalStats := conn.ConnectionStats()
	result.PacketsSent = finalStats.PacketsSent
	result.PacketsReceived = finalStats.PacketsReceived
	result.PacketsLost = finalStats.PacketsLost

	// Get final RTT stats
	result.RTTMin = finalStats.MinRTT
	result.RTTSmoothed = finalStats.SmoothedRTT
	result.RTTLatest = finalStats.LatestRTT

	log.Printf("[CLIENT] Transfer complete: %d bytes in %v (%.2f Mbps)",
		bytesReceived, result.TransferDuration, result.Throughput)

	return result
}

// mapSecurityLevels maps the mode and security level to ML-KEM and ML-DSA levels
func mapSecurityLevels(mode string, securityLevel int) (mlkemLevel, mldsaLevel int) {
	if mode == "classical" {
		return 0, 0 // Classical mode doesn't use PQC
	}

	// For PQC and hybrid modes, map security level to specific algorithms
	switch securityLevel {
	case 512:
		return 512, 44 // ML-KEM-512 with ML-DSA-44 (NIST Level 1)
	case 768:
		return 768, 65 // ML-KEM-768 with ML-DSA-65 (NIST Level 3)
	case 1024:
		return 1024, 87 // ML-KEM-1024 with ML-DSA-87 (NIST Level 5)
	default:
		return 768, 65 // Default to NIST Level 3
	}
}

func init() {
	// Disable QLOG for cleaner output
	os.Setenv("QLOGDIR", "")
}
