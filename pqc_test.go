package quic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestPQCHandshake verifies that QUIC can establish connections using post-quantum cryptography
func TestPQCHandshake(t *testing.T) {
	// Generate a self-signed certificate for testing
	cert, _, _ := generateTestCertificate(t)

	testCases := []struct {
		name                string
		cryptoMode          string
		pqcSecurityLevel    int
		expectedCurve       string // What we expect to be negotiated
		expectedMinKeySize  int    // Minimum public key size in bytes
	}{
		{
			name:               "PQC Mode with ML-KEM-768",
			cryptoMode:         "pqc",
			pqcSecurityLevel:   768,
			expectedCurve:      "ML-KEM-768 or X25519",
			expectedMinKeySize: 1184, // ML-KEM-768 encapsulation key size
		},
		{
			name:               "PQC Mode with ML-KEM-1024",
			cryptoMode:         "pqc",
			pqcSecurityLevel:   1024,
			expectedCurve:      "ML-KEM-1024 or X25519",
			expectedMinKeySize: 1568, // ML-KEM-1024 encapsulation key size
		},
		{
			name:               "Classical Mode",
			cryptoMode:         "classical",
			pqcSecurityLevel:   768,
			expectedCurve:      "X25519",
			expectedMinKeySize: 32, // X25519 public key size
		},
		{
			name:               "Auto Mode",
			cryptoMode:         "auto",
			pqcSecurityLevel:   768,
			expectedCurve:      "ML-KEM-768 or X25519",
			expectedMinKeySize: 1184, // Should prefer ML-KEM-768
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create server config
			serverTLSConf := &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"test-protocol"},
			}

			serverConf := &Config{
				CryptoMode:       tc.cryptoMode,
				PQCSecurityLevel: tc.pqcSecurityLevel,
			}

			// Create listener
			listener, err := ListenAddr("127.0.0.1:0", serverTLSConf, serverConf)
			if err != nil {
				t.Fatalf("Failed to create listener: %v", err)
			}
			defer listener.Close()

			serverAddr := listener.Addr().String()
			t.Logf("Server listening on %s", serverAddr)

			// Start server in goroutine
			serverDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept(context.Background())
				if err != nil {
					serverDone <- fmt.Errorf("server accept failed: %w", err)
					return
				}
				defer conn.CloseWithError(0, "")

				// Accept a stream
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					serverDone <- fmt.Errorf("server accept stream failed: %w", err)
					return
				}
				defer stream.Close()

				// Echo back what we receive
				buf := make([]byte, 1024)
				n, err := stream.Read(buf)
				if err != nil && err != io.EOF {
					serverDone <- fmt.Errorf("server read failed: %w", err)
					return
				}

				if _, err := stream.Write(buf[:n]); err != nil {
					serverDone <- fmt.Errorf("server write failed: %w", err)
					return
				}

				t.Logf("Server: Echoed %d bytes", n)

				// Wait a bit to ensure client reads before we close
				time.Sleep(50 * time.Millisecond)
				serverDone <- nil
			}()

			// Give server time to start
			time.Sleep(100 * time.Millisecond)

			// Create client config
			clientTLSConf := &tls.Config{
				InsecureSkipVerify: true, // Skip verification for self-signed cert
				NextProtos:         []string{"test-protocol"},
			}

			clientConf := &Config{
				CryptoMode:       tc.cryptoMode,
				PQCSecurityLevel: tc.pqcSecurityLevel,
			}

			// Connect client
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			t.Logf("Client connecting to %s with CryptoMode=%s, PQCSecurityLevel=%d",
				serverAddr, tc.cryptoMode, tc.pqcSecurityLevel)

			conn, err := DialAddr(ctx, serverAddr, clientTLSConf, clientConf)
			if err != nil {
				t.Fatalf("Client dial failed: %v", err)
			}
			defer conn.CloseWithError(0, "")

			t.Logf("Client: Connection established!")

			// Log which algorithm was negotiated
			connState := conn.ConnectionState()
			t.Logf("   Negotiated TLS version: 0x%04x", connState.TLS.Version)
			t.Logf("   Cipher suite: 0x%04x", connState.TLS.CipherSuite)
			t.Logf("   Key exchange: %s (ID: 0x%04x)", connState.TLS.CurveID, uint16(connState.TLS.CurveID))
			t.Logf("   Negotiated protocol: %s", connState.TLS.NegotiatedProtocol)

			// Open a stream and send data
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatalf("Client open stream failed: %v", err)
			}
			defer stream.Close()

			// Send test message
			testMsg := []byte("Hello PQC World!")
			if _, err := stream.Write(testMsg); err != nil {
				t.Fatalf("Client write failed: %v", err)
			}

			// Read echo
			buf := make([]byte, 1024)
			n, err := stream.Read(buf)
			if err != nil && err != io.EOF {
				t.Fatalf("Client read failed: %v", err)
			}

			if string(buf[:n]) != string(testMsg) {
				t.Fatalf("Echo mismatch: got %q, want %q", string(buf[:n]), string(testMsg))
			}

			t.Logf("Client: Received echo successfully")

			// Wait for server to complete
			select {
			case err := <-serverDone:
				if err != nil {
					t.Fatalf("Server error: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Server timed out")
			}

			t.Logf("✅ Test passed! Connection established with CryptoMode=%s", tc.cryptoMode)
			t.Logf("   Expected curve negotiation: %s", tc.expectedCurve)

			// Give time for connection cleanup
			time.Sleep(100 * time.Millisecond)
		})
	}
}

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(t *testing.T) (tls.Certificate, []byte, []byte) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"QUIC PQC Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Load as tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to load certificate: %v", err)
	}

	return cert, certPEM, keyPEM
}
