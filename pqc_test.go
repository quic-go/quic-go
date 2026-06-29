package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/pqctls"

	"github.com/stretchr/testify/require"
)

// TestPQCHandshake verifies that QUIC establishes connections using the post-quantum
// cryptography provided natively by the (patched) standard library, selected entirely
// through tls.Config: ML-KEM key exchange via CurvePreferences and ML-DSA
// authentication via Certificates. There are no PQC-specific fields on quic.Config.
func TestPQCHandshake(t *testing.T) {
	classicalCert := generateClassicalTestCertificate(t)
	mldsa65Cert, err := pqctls.GenerateMLDSACertificate(pqctls.MLDSA65, "QUIC PQC Test", []string{"localhost"}, time.Hour)
	require.NoError(t, err)
	mldsa87Cert, err := pqctls.GenerateMLDSACertificate(pqctls.MLDSA87, "QUIC PQC Test", []string{"localhost"}, time.Hour)
	require.NoError(t, err)
	hybridCert, err := pqctls.GenerateHybridCertificate(pqctls.MLDSA65, "QUIC Hybrid Test", []string{"localhost"}, time.Hour)
	require.NoError(t, err)

	testCases := []struct {
		name  string
		curve tls.CurveID
		cert  tls.Certificate
		// sigScheme, when non-zero, is advertised by the client so a composite
		// certificate can be selected and verified.
		sigScheme tls.SignatureScheme
	}{
		{name: "Classical (X25519 + ECDSA)", curve: tls.X25519, cert: classicalCert},
		{name: "Pure ML-KEM-768 + ML-DSA-65", curve: pqctls.MLKEM768, cert: mldsa65Cert},
		{name: "Pure ML-KEM-1024 + ML-DSA-87", curve: pqctls.MLKEM1024, cert: mldsa87Cert},
		{name: "Hybrid X25519+ML-KEM-768 + ML-DSA-65", curve: pqctls.X25519MLKEM768, cert: mldsa65Cert},
		{name: "Hybrid KEX + Composite Ed25519+ML-DSA-65 cert", curve: pqctls.X25519MLKEM768, cert: hybridCert, sigScheme: pqctls.CompositeEd25519MLDSA65},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serverTLSConf := &tls.Config{
				Certificates:     []tls.Certificate{tc.cert},
				NextProtos:       []string{"pqc-test"},
				CurvePreferences: []tls.CurveID{tc.curve},
			}
			clientTLSConf := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"pqc-test"},
				CurvePreferences:   []tls.CurveID{tc.curve},
			}
			if tc.sigScheme != 0 {
				// The client must advertise the composite scheme to accept a
				// composite server certificate.
				clientTLSConf.SignatureSchemes = []tls.SignatureScheme{tc.sigScheme}
			}

			serverTr := &Transport{Conn: newUDPConnLocalhost(t)}
			defer serverTr.Close()
			ln, err := serverTr.Listen(serverTLSConf, nil)
			require.NoError(t, err)
			defer ln.Close()

			serverErr := make(chan error, 1)
			go func() {
				conn, err := ln.Accept(context.Background())
				if err != nil {
					serverErr <- err
					return
				}
				str, err := conn.AcceptStream(context.Background())
				if err != nil {
					serverErr <- err
					return
				}
				data, err := io.ReadAll(str)
				if err != nil {
					serverErr <- err
					return
				}
				if _, err := str.Write(data); err != nil {
					serverErr <- err
					return
				}
				str.Close()
				<-conn.Context().Done()
				serverErr <- nil
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			clientTr := &Transport{Conn: newUDPConnLocalhost(t)}
			defer clientTr.Close()
			conn, err := clientTr.Dial(ctx, ln.Addr(), clientTLSConf, nil)
			require.NoError(t, err)

			negotiated := conn.ConnectionState().TLS.CurveID
			t.Logf("negotiated curve: 0x%04x, cipher: 0x%04x", uint16(negotiated), conn.ConnectionState().TLS.CipherSuite)
			require.Equal(t, tc.curve, negotiated, "negotiated curve must match the requested curve")

			str, err := conn.OpenStreamSync(ctx)
			require.NoError(t, err)
			msg := []byte("hello post-quantum world")
			_, err = str.Write(msg)
			require.NoError(t, err)
			require.NoError(t, str.Close())

			echo, err := io.ReadAll(str)
			require.NoError(t, err)
			require.Equal(t, msg, echo)

			conn.CloseWithError(0, "")
			require.NoError(t, <-serverErr)
		})
	}
}

// generateClassicalTestCertificate creates a self-signed ECDSA certificate for the
// classical baseline.
func generateClassicalTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"QUIC Classical Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return cert
}
