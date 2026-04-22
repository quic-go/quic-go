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
	"path/filepath"
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
	outputFile    = flag.String("output", "benchmark_results.csv", "Output CSV file")
	iterations    = flag.Int("iterations", 10, "Iterations per mode")
	dataSize      = flag.Int("size", 1048576, "Data size in bytes (default: 1MB)")
	securityLevel = flag.Int("security", 768, "PQC security level: 768 or 1024")
	runClassic    = flag.Bool("classic", true, "Run classic benchmarks")
	runPQC        = flag.Bool("pqc", true, "Run PQC benchmarks")
	serverAddr    = flag.String("server", "127.0.0.1:4433", "Server address")
	buildOnly     = flag.Bool("build-only", false, "Only build binaries, don't run tests")
	skipBuild     = flag.Bool("skip-build", false, "Skip building binaries (use prebuilt ones in CWD or ./benchmark/)")
)

var resultRegex = regexp.MustCompile(`BENCHMARK_RESULT: (.+)$`)

func main() {
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("=== QUIC PQC Benchmark Runner ===")

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

	// Prepare results
	var allResults []BenchmarkResult
	var mu sync.Mutex

	// Run classical benchmarks
	if *runClassic {
		log.Println("\n=== Running Classical Benchmarks ===")
		results := runBenchmarkSuite("classical", *iterations)
		mu.Lock()
		allResults = append(allResults, results...)
		mu.Unlock()
	}

	// Run PQC benchmarks
	if *runPQC {
		log.Println("\n=== Running PQC Benchmarks ===")
		results := runBenchmarkSuite("pqc", *iterations)
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

	// Determine if we're in the benchmark directory or parent directory
	benchmarkDir := "."
	_, err := os.Stat("server")
	if err != nil {
		// We're in parent directory
		benchmarkDir = "benchmark"
	}

	// Build server
	log.Println("  Building server...")
	serverCmd := exec.Command("go", "build", "-o", filepath.Join(benchmarkDir, "benchmark_server"), "./server")
	serverCmd.Dir = benchmarkDir
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Run(); err != nil {
		return fmt.Errorf("failed to build server: %w", err)
	}

	// Build client
	log.Println("  Building client...")
	clientCmd := exec.Command("go", "build", "-o", filepath.Join(benchmarkDir, "benchmark_client"), "./client")
	clientCmd.Dir = benchmarkDir
	clientCmd.Stdout = os.Stdout
	clientCmd.Stderr = os.Stderr
	if err := clientCmd.Run(); err != nil {
		return fmt.Errorf("failed to build client: %w", err)
	}

	log.Println("  Build complete!")
	return nil
}

func runBenchmarkSuite(mode string, iterations int) []BenchmarkResult {
	log.Printf("Starting %s benchmark suite (%d iterations)", mode, iterations)

	var results []BenchmarkResult

	// Determine binary paths
	serverBin := "./benchmark_server"
	clientBin := "./benchmark_client"
	if _, err := os.Stat("benchmark/benchmark_server"); err == nil {
		serverBin = filepath.Join("benchmark", "benchmark_server")
		clientBin = filepath.Join("benchmark", "benchmark_client")
	}

	// Start server
	serverCmd := exec.Command(serverBin,
		"-mode", mode,
		"-security", fmt.Sprintf("%d", *securityLevel),
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
			if strings.Contains(line, "BENCHMARK_RESULT") {
				if result := parseResult(line); result != nil {
					log.Printf("[SERVER] Result: %.2f Mbps", result.Throughput)
				}
			} else {
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
		"-security", fmt.Sprintf("%d", *securityLevel),
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

	log.Printf("Completed %s benchmark: %d results collected", mode, len(results))
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
	classicalResults := filterResults(results, "classical")
	pqcResults := filterResults(results, "pqc")

	log.Println("\n=== Summary ===")

	if len(classicalResults) > 0 {
		log.Println("\nClassical Mode:")
		printStats("  Handshake", classicalResults, func(r BenchmarkResult) float64 {
			return float64(r.HandshakeDuration) / 1e6
		}, "ms")
		printStats("  Throughput", classicalResults, func(r BenchmarkResult) float64 {
			return r.Throughput
		}, "Mbps")
	}

	if len(pqcResults) > 0 {
		log.Println("\nPQC Mode:")
		printStats("  Handshake", pqcResults, func(r BenchmarkResult) float64 {
			return float64(r.HandshakeDuration) / 1e6
		}, "ms")
		printStats("  Throughput", pqcResults, func(r BenchmarkResult) float64 {
			return r.Throughput
		}, "Mbps")
	}

	if len(classicalResults) > 0 && len(pqcResults) > 0 {
		classicalHandshake := avg(classicalResults, func(r BenchmarkResult) float64 {
			return float64(r.HandshakeDuration) / 1e6
		})
		pqcHandshake := avg(pqcResults, func(r BenchmarkResult) float64 {
			return float64(r.HandshakeDuration) / 1e6
		})
		overhead := ((pqcHandshake - classicalHandshake) / classicalHandshake) * 100

		log.Printf("\nPQC Overhead: %.1f%% increase in handshake time", overhead)
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
