// Command pqc_server is a minimal QUIC echo server demonstrating post-quantum
// cryptography in quic-go, configured entirely through crypto/tls: ML-KEM key
// exchange via CurvePreferences and ML-DSA authentication via a certificate from
// the pqctls package. ML-KEM and ML-DSA are provided natively by the standard
// library (pure ML-KEM-768 requires the project's patched Go toolchain).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/pqctls"
)

func main() {
	addr := flag.String("addr", "localhost:4433", "address to listen on")
	mode := flag.String("mode", "mlkem768", "classical | mlkem768 | mlkem1024 | hybrid")
	flag.Parse()

	curve, cert, err := serverConfig(*mode)
	if err != nil {
		log.Fatal(err)
	}

	tlsConf := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		NextProtos:       []string{"pqc-echo"},
		CurvePreferences: []tls.CurveID{curve},
	}

	ln, err := quic.ListenAddr(*addr, tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	log.Printf("PQC echo server listening on %s (mode=%s, curve=0x%04x)", *addr, *mode, uint16(curve))

	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		go handle(conn)
	}
}

func handle(conn *quic.Conn) {
	defer conn.CloseWithError(0, "")
	cs := conn.ConnectionState().TLS
	log.Printf("handshake complete: curve=0x%04x cipher=0x%04x", uint16(cs.CurveID), cs.CipherSuite)

	str, err := conn.AcceptStream(context.Background())
	if err != nil {
		return
	}
	data, err := io.ReadAll(str)
	if err != nil {
		return
	}
	if _, err := str.Write(data); err != nil {
		return
	}
	str.Close() // FIN so the client's ReadAll completes
	<-conn.Context().Done()
}

func serverConfig(mode string) (tls.CurveID, tls.Certificate, error) {
	switch mode {
	case "classical":
		cert, err := classicalCertificate()
		return tls.X25519, cert, err
	case "mlkem768":
		cert, err := pqctls.GenerateMLDSACertificate(pqctls.MLDSA65, "quic-go PQC", []string{"localhost"}, 24*time.Hour)
		return pqctls.MLKEM768, cert, err
	case "mlkem1024":
		cert, err := pqctls.GenerateMLDSACertificate(pqctls.MLDSA87, "quic-go PQC", []string{"localhost"}, 24*time.Hour)
		return pqctls.MLKEM1024, cert, err
	case "hybrid":
		cert, err := pqctls.GenerateMLDSACertificate(pqctls.MLDSA65, "quic-go PQC", []string{"localhost"}, 24*time.Hour)
		return pqctls.X25519MLKEM768, cert, err
	default:
		return 0, tls.Certificate{}, fmt.Errorf("unknown mode %q", mode)
	}
}

func classicalCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"quic-go Classical"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
