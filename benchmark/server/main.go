package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

var (
	addr          = flag.String("addr", "0.0.0.0:4433", "Address to listen on")
	mode          = flag.String("mode", "classical", "Crypto mode: classical, pqc, or hybrid")
	securityLevel = flag.Int("security", 768, "PQC security level: 768 or 1024")
	dataSize      = flag.Int("size", 1048576, "Total data size to transfer (bytes)")
	chunkSize     = flag.Int("chunk", 1048576, "Chunk size (bytes)")
)

func main() {
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Printf("[SERVER] Starting QUIC benchmark server")
	log.Printf("[SERVER] Mode: %s, SecurityLevel: %d, DataSize: %d bytes", *mode, *securityLevel, *dataSize)

	// Generate certificate
	cert, err := generateCertificate()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"benchmark"},
		MinVersion:   tls.VersionTLS13,
	}

	// Configure QUIC
	quicConfig := &quic.Config{
		CryptoMode:       *mode,
		PQCSecurityLevel: *securityLevel,
		MaxIdleTimeout:   30 * time.Second,
	}

	// Create listener
	listener, err := quic.ListenAddr(*addr, tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	log.Printf("[SERVER] Listening on %s", *addr)

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

func handleConnection(conn *quic.Conn) {
	defer conn.CloseWithError(0, "")

	log.Printf("[SERVER] Connection from %s", conn.RemoteAddr())

	// Wait for stream from client
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		log.Printf("[SERVER] AcceptStream error: %v", err)
		return
	}
	defer stream.Close()

	log.Printf("[SERVER] Stream accepted, waiting for ready signal")

	// Read ready signal from client
	readyBuf := make([]byte, 1)
	_, err = stream.Read(readyBuf)
	if err != nil {
		log.Printf("[SERVER] Failed to read ready signal: %v", err)
		return
	}

	log.Printf("[SERVER] Ready signal received, starting data transfer")

	// Send data
	transferStart := time.Now()
	chunkLen := *chunkSize
	if chunkLen > *dataSize {
		chunkLen = *dataSize
	}
	chunk := make([]byte, chunkLen)
	rand.Read(chunk)

	var bytesTransferred int64
	for bytesTransferred < int64(*dataSize) {
		remaining := int64(*dataSize) - bytesTransferred
		toWrite := chunk
		if int64(len(toWrite)) > remaining {
			toWrite = chunk[:remaining]
		}
		n, err := stream.Write(toWrite)
		if err != nil {
			log.Printf("[SERVER] Write error: %v", err)
			return
		}
		bytesTransferred += int64(n)
	}

	transferDuration := time.Since(transferStart)
	throughputMbps := float64(bytesTransferred*8) / transferDuration.Seconds() / 1e6

	log.Printf("[SERVER] Completed: %d bytes in %v (%.2f Mbps)",
		bytesTransferred, transferDuration, throughputMbps)

	// Close stream to signal EOF
	stream.Close()

	// Brief delay to ensure data is flushed before connection closes
	time.Sleep(100 * time.Millisecond)
}

func generateCertificate() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"QUIC PQC Benchmark"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("10.0.2.15"),
			net.ParseIP("192.168.100.2"),
		},
		DNSNames: []string{"localhost", "server"},
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

func init() {
	// Disable QLOG for cleaner output
	os.Setenv("QLOGDIR", "")
}
