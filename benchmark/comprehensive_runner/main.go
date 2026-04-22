package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// BenchmarkResult represents a single test result
type BenchmarkResult struct {
	// Basic Info
	Mode              string        `json:"mode"`
	Iteration         int           `json:"iteration"`
	Timestamp         string        `json:"timestamp"`
	Error             string        `json:"error,omitempty"`

	// PQC Security Levels
	MLKEMLevel        int           `json:"mlkem_level"`
	MLDSALevel        int           `json:"mldsa_level"`

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
	BytesTransferred  int64         `json:"bytes_transferred"`
	TransferDuration  time.Duration `json:"transfer_duration_ns"`
	TotalDuration     time.Duration `json:"total_duration_ns"`
	Throughput        float64       `json:"throughput_mbps"`

	// E. Crypto Info
	CipherSuite       string        `json:"cipher_suite"`
	CurveID           string        `json:"curve_id"`
	CertChainSize     int           `json:"cert_chain_size_bytes"`

	// F. Resource Usage
	StreamsCreated    uint64        `json:"streams_created"`
}

var (
	outputFile = flag.String("output", "comprehensive_results.csv", "Output CSV file")
	iterations = flag.Int("iterations", 10, "Iterations per configuration")
	dataSize   = flag.Int("size", 1048576, "Data size in bytes (default: 1MB)")
	serverAddr = flag.String("server", "127.0.0.1:4433", "Server address")
	buildOnly  = flag.Bool("build-only", false, "Only build binaries, don't run tests")
	skipBuild  = flag.Bool("skip-build", false, "Skip building binaries (use prebuilt ones in CWD or ./benchmark/)")
)

var resultRegex = regexp.MustCompile(`BENCHMARK_RESULT: (.+)$`)

// Configuration represents a test configuration
type Configuration struct {
	Mode          string
	SecurityLevel int
	Name          string
}

func main() {
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("=== QUIC PQC Comprehensive Benchmark Runner ===")
	log.Printf("This runner will test:")
	log.Printf("  - Classical mode (X25519)")
	log.Printf("  - PQC ML-KEM-512 (NIST Level 1)")
	log.Printf("  - PQC ML-KEM-768 (NIST Level 3)")
	log.Printf("  - PQC ML-KEM-1024 (NIST Level 5)")
	log.Printf("  - %d iterations per configuration", *iterations)
	log.Printf("  - %d bytes data transfer per test", *dataSize)

	// Build binaries (skippable when prebuilt)
	if !*skipBuild {
		if err := buildBinaries(); err != nil {
			log.Fatalf("Failed to build binaries: %v", err)
		}
		if *buildOnly {
			log.Println("Build completed. Exiting (build-only mode).")
			return
		}
	} else {
		log.Println("Skipping build (--skip-build set)")
	}

	// Define all test configurations
	configurations := []Configuration{
		{Mode: "classical", SecurityLevel: 0, Name: "Classical (X25519)"},
		{Mode: "pqc", SecurityLevel: 512, Name: "PQC ML-KEM-512 + ML-DSA-44"},
		{Mode: "pqc", SecurityLevel: 768, Name: "PQC ML-KEM-768 + ML-DSA-65"},
		{Mode: "pqc", SecurityLevel: 1024, Name: "PQC ML-KEM-1024 + ML-DSA-87"},
		{Mode: "hybrid", SecurityLevel: 768, Name: "Hybrid Ed25519+ML-DSA-65 / X25519+ML-KEM-768"},
		{Mode: "hybrid", SecurityLevel: 1024, Name: "Hybrid Ed25519+ML-DSA-87 / X25519+ML-KEM-1024"},
	}

	// Prepare results
	var allResults []BenchmarkResult
	var mu sync.Mutex

	// Run all configurations
	totalConfigs := len(configurations)
	for i, config := range configurations {
		log.Printf("\n=== [%d/%d] Running: %s ===", i+1, totalConfigs, config.Name)
		results := runBenchmarkSuite(config.Mode, config.SecurityLevel, *iterations)
		mu.Lock()
		allResults = append(allResults, results...)
		mu.Unlock()
	}

	// Write results to CSV
	if err := writeCSV(*outputFile, allResults); err != nil {
		log.Fatalf("Failed to write CSV: %v", err)
	}

	log.Printf("\n=== Benchmark Complete ===")
	log.Printf("Total tests: %d", len(allResults))
	log.Printf("Results written to: %s", *outputFile)

	// Print summary
	printSummary(allResults)
}

func buildBinaries() error {
	log.Println("Building binaries...")

	// When run from benchmark/, we need to build in the current directory
	// The binary is in benchmark/, server/ and client/ are also in benchmark/
	benchmarkDir := "."

	// Check if we're actually in the benchmark directory by looking for server/ and client/
	if _, err := os.Stat("server"); os.IsNotExist(err) {
		// We might be in a subdirectory, go up one level
		benchmarkDir = ".."
	}

	// Build server
	log.Println("  Building server...")
	serverCmd := exec.Command("go", "build", "-o", "benchmark_server", "./server")
	serverCmd.Dir = benchmarkDir
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Run(); err != nil {
		return fmt.Errorf("failed to build server: %w", err)
	}

	// Build client
	log.Println("  Building client...")
	clientCmd := exec.Command("go", "build", "-o", "benchmark_client", "./client")
	clientCmd.Dir = benchmarkDir
	clientCmd.Stdout = os.Stdout
	clientCmd.Stderr = os.Stderr
	if err := clientCmd.Run(); err != nil {
		return fmt.Errorf("failed to build client: %w", err)
	}

	log.Println("  Build complete!")
	return nil
}

func runBenchmarkSuite(mode string, securityLevel int, iterations int) []BenchmarkResult {
	secLevelStr := fmt.Sprintf("%d", securityLevel)
	if mode == "classical" {
		secLevelStr = "0"
	}

	log.Printf("Starting %s (security=%s) benchmark suite (%d iterations)", mode, secLevelStr, iterations)

	var results []BenchmarkResult

	// Binary paths - check if we're in benchmark/ or in a subdirectory
	serverBin := "./benchmark_server"
	clientBin := "./benchmark_client"

	// If server binary doesn't exist in current dir, try parent
	if _, err := os.Stat(serverBin); os.IsNotExist(err) {
		serverBin = "../benchmark_server"
		clientBin = "../benchmark_client"
	}

	// Start server
	serverCmd := exec.Command(serverBin,
		"-mode", mode,
		"-security", secLevelStr,
		"-addr", *serverAddr,
		"-size", fmt.Sprintf("%d", *dataSize),
	)

	serverStdout, _ := serverCmd.StdoutPipe()
	serverStderr, _ := serverCmd.StderrPipe()

	if err := serverCmd.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		serverCmd.Process.Kill()
		serverCmd.Wait()
	}()

	// Capture server output in background
	go func() {
		scanner := bufio.NewScanner(serverStdout)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, "BENCHMARK_RESULT") {
				log.Printf("[SERVER] %s", line)
			}
		}
	}()

	go func() {
		io.Copy(os.Stderr, serverStderr)
	}()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Start client
	clientCmd := exec.Command(clientBin,
		"-mode", mode,
		"-security", secLevelStr,
		"-server", *serverAddr,
		"-iterations", fmt.Sprintf("%d", iterations),
	)

	clientStdout, _ := clientCmd.StdoutPipe()
	clientStderr, _ := clientCmd.StderrPipe()

	if err := clientCmd.Start(); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	// Capture client output
	go func() {
		scanner := bufio.NewScanner(clientStdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "BENCHMARK_RESULT") {
				if result := parseResult(line); result != nil {
					results = append(results, *result)
				}
			} else {
				log.Printf("[CLIENT] %s", line)
			}
		}
	}()

	go func() {
		io.Copy(os.Stderr, clientStderr)
	}()

	// Wait for client to complete
	if err := clientCmd.Wait(); err != nil {
		log.Printf("Client exited with error: %v", err)
	}

	// Give server time to finish
	time.Sleep(1 * time.Second)

	log.Printf("Completed %s (security=%s) benchmark: %d results collected", mode, secLevelStr, len(results))
	return results
}

func parseResult(line string) *BenchmarkResult {
	matches := resultRegex.FindStringSubmatch(line)
	if len(matches) < 2 {
		return nil
	}

	var result BenchmarkResult
	if err := json.Unmarshal([]byte(matches[1]), &result); err != nil {
		log.Printf("Failed to parse result: %v", err)
		return nil
	}

	return &result
}

func writeCSV(filename string, results []BenchmarkResult) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		// Basic Info
		"mode",
		"iteration",
		"timestamp",
		// PQC Security
		"mlkem_level",
		"mldsa_level",
		// A. Connection Establishment
		"handshake_duration_ms",
		"packets_sent",
		"packets_received",
		"handshake_bytes_sent",
		"handshake_bytes_recv",
		"time_to_first_byte_ms",
		// B. Loss Recovery & Reliability
		"rtt_min_ms",
		"rtt_smoothed_ms",
		"rtt_latest_ms",
		"packets_lost",
		// C. Flow & Congestion Control
		"congestion_window_bytes",
		"bytes_in_flight",
		// D. Data Transfer
		"transfer_duration_ms",
		"total_duration_ms",
		"bytes_transferred",
		"throughput_mbps",
		// E. Crypto Info
		"cipher_suite",
		"curve_id",
		"cert_chain_size_bytes",
		// F. Resource Usage
		"streams_created",
		// Error
		"error",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write rows
	for _, r := range results {
		bytes := r.BytesReceived
		if bytes == 0 {
			bytes = r.BytesTransferred
		}

		row := []string{
			// Basic Info
			r.Mode,
			fmt.Sprintf("%d", r.Iteration),
			r.Timestamp,
			// PQC Security
			fmt.Sprintf("%d", r.MLKEMLevel),
			fmt.Sprintf("%d", r.MLDSALevel),
			// A. Connection Establishment
			fmt.Sprintf("%.3f", float64(r.HandshakeDuration)/1e6),
			fmt.Sprintf("%d", r.PacketsSent),
			fmt.Sprintf("%d", r.PacketsReceived),
			fmt.Sprintf("%d", r.HandshakeBytesSent),
			fmt.Sprintf("%d", r.HandshakeBytesRecv),
			fmt.Sprintf("%.3f", float64(r.TimeToFirstByte)/1e6),
			// B. Loss Recovery & Reliability
			fmt.Sprintf("%.3f", float64(r.RTTMin)/1e6),
			fmt.Sprintf("%.3f", float64(r.RTTSmoothed)/1e6),
			fmt.Sprintf("%.3f", float64(r.RTTLatest)/1e6),
			fmt.Sprintf("%d", r.PacketsLost),
			// C. Flow & Congestion Control
			fmt.Sprintf("%d", r.CongestionWindow),
			fmt.Sprintf("%d", r.BytesInFlight),
			// D. Data Transfer
			fmt.Sprintf("%.3f", float64(r.TransferDuration)/1e6),
			fmt.Sprintf("%.3f", float64(r.TotalDuration)/1e6),
			fmt.Sprintf("%d", bytes),
			fmt.Sprintf("%.2f", r.Throughput),
			// E. Crypto Info
			r.CipherSuite,
			r.CurveID,
			fmt.Sprintf("%d", r.CertChainSize),
			// F. Resource Usage
			fmt.Sprintf("%d", r.StreamsCreated),
			// Error
			r.Error,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func printSummary(results []BenchmarkResult) {
	log.Println("\n=== Comprehensive Summary ===")

	// Group by mode and security level
	type ConfigKey struct {
		Mode          string
		MLKEMLevel    int
	}

	groupedResults := make(map[ConfigKey][]BenchmarkResult)
	for _, r := range results {
		if r.Error == "" {
			key := ConfigKey{Mode: r.Mode, MLKEMLevel: r.MLKEMLevel}
			groupedResults[key] = append(groupedResults[key], r)
		}
	}

	// Print results for each configuration
	configs := []ConfigKey{
		{Mode: "classical", MLKEMLevel: 0},
		{Mode: "pqc", MLKEMLevel: 512},
		{Mode: "pqc", MLKEMLevel: 768},
		{Mode: "pqc", MLKEMLevel: 1024},
	}

	baselineHandshake := 0.0
	baselineThroughput := 0.0

	for i, config := range configs {
		configResults := groupedResults[config]
		if len(configResults) == 0 {
			continue
		}

		// Determine name
		var name string
		if config.Mode == "classical" {
			name = "Classical (X25519)"
		} else {
			name = fmt.Sprintf("PQC ML-KEM-%d", config.MLKEMLevel)
		}

		log.Printf("\n%s:", name)

		avgHandshake := avg(configResults, func(r BenchmarkResult) float64 {
			return float64(r.HandshakeDuration) / 1e6
		})
		avgThroughput := avg(configResults, func(r BenchmarkResult) float64 {
			return r.Throughput
		})
		avgCertSize := avg(configResults, func(r BenchmarkResult) float64 {
			return float64(r.CertChainSize)
		})

		printStats("  Handshake", configResults, func(r BenchmarkResult) float64 {
			return float64(r.HandshakeDuration) / 1e6
		}, "ms")
		printStats("  Throughput", configResults, func(r BenchmarkResult) float64 {
			return r.Throughput
		}, "Mbps")
		log.Printf("  Certificate Size: avg=%.0f bytes", avgCertSize)

		// Track baseline for comparison
		if i == 0 {
			baselineHandshake = avgHandshake
			baselineThroughput = avgThroughput
		} else {
			handshakeOverhead := ((avgHandshake - baselineHandshake) / baselineHandshake) * 100
			throughputChange := ((avgThroughput - baselineThroughput) / baselineThroughput) * 100
			certSizeIncrease := avgCertSize - avg(groupedResults[configs[0]], func(r BenchmarkResult) float64 {
				return float64(r.CertChainSize)
			})

			log.Printf("  vs Classical: handshake %+.1f%%, throughput %+.1f%%, cert size %+.0f bytes",
				handshakeOverhead, throughputChange, certSizeIncrease)
		}
	}

	log.Println("\n=== Summary Table ===")
	log.Printf("%-25s | %15s | %15s | %15s", "Configuration", "Handshake (ms)", "Throughput (Mbps)", "Cert Size (B)")
	log.Printf("%-25s-+-%15s-+-%15s-+-%15s", strings.Repeat("-", 25), strings.Repeat("-", 15), strings.Repeat("-", 15), strings.Repeat("-", 15))

	for _, config := range configs {
		configResults := groupedResults[config]
		if len(configResults) == 0 {
			continue
		}

		var name string
		if config.Mode == "classical" {
			name = "Classical (X25519)"
		} else {
			name = fmt.Sprintf("PQC ML-KEM-%d", config.MLKEMLevel)
		}

		avgHandshake := avg(configResults, func(r BenchmarkResult) float64 {
			return float64(r.HandshakeDuration) / 1e6
		})
		avgThroughput := avg(configResults, func(r BenchmarkResult) float64 {
			return r.Throughput
		})
		avgCertSize := avg(configResults, func(r BenchmarkResult) float64 {
			return float64(r.CertChainSize)
		})

		log.Printf("%-25s | %15.2f | %15.2f | %15.0f", name, avgHandshake, avgThroughput, avgCertSize)
	}
}

func filterResults(results []BenchmarkResult, mode string) []BenchmarkResult {
	var filtered []BenchmarkResult
	for _, r := range results {
		if r.Mode == mode && r.Error == "" {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func printStats(label string, results []BenchmarkResult, extractor func(BenchmarkResult) float64, unit string) {
	if len(results) == 0 {
		return
	}

	values := make([]float64, len(results))
	for i, r := range results {
		values[i] = extractor(r)
	}

	avgVal := avg(results, extractor)
	minVal := min(values)
	maxVal := max(values)

	log.Printf("%s: avg=%.2f %s, min=%.2f %s, max=%.2f %s",
		label, avgVal, unit, minVal, unit, maxVal, unit)
}

func avg(results []BenchmarkResult, extractor func(BenchmarkResult) float64) float64 {
	if len(results) == 0 {
		return 0
	}
	sum := 0.0
	for _, r := range results {
		sum += extractor(r)
	}
	return sum / float64(len(results))
}

func min(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	minVal := values[0]
	for _, v := range values[1:] {
		if v < minVal {
			minVal = v
		}
	}
	return minVal
}

func max(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	maxVal := values[0]
	for _, v := range values[1:] {
		if v > maxVal {
			maxVal = v
		}
	}
	return maxVal
}
