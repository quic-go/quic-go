package pqctls

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestCompositeQUICTLS drives a composite handshake through the tls.QUICServer /
// tls.QUICClient API (the exact API quic-go uses), to isolate QUIC-TLS behaviour.
func TestCompositeQUICTLS(t *testing.T) {
	cert, err := GenerateHybridCertificate(MLDSA65, "smoke", []string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := tls.QUICServer(&tls.QUICConfig{EnableSessionEvents: true, TLSConfig: &tls.Config{
		Certificates:     []tls.Certificate{cert},
		NextProtos:       []string{"pqc-test"},
		CurvePreferences: []tls.CurveID{X25519MLKEM768},
	}})
	client := tls.QUICClient(&tls.QUICConfig{EnableSessionEvents: true, TLSConfig: &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"pqc-test"},
		CurvePreferences:   []tls.CurveID{X25519MLKEM768},
		SignatureSchemes:   []tls.SignatureScheme{CompositeEd25519MLDSA65},
	}})
	ctx := context.Background()
	client.SetTransportParameters([]byte("client-tp"))
	server.SetTransportParameters([]byte("server-tp"))
	if err := client.Start(ctx); err != nil {
		t.Fatalf("client start: %v", err)
	}
	if err := server.Start(ctx); err != nil {
		t.Fatalf("server start: %v", err)
	}
	pump := func(src, dst *tls.QUICConn) error {
		for {
			e := src.NextEvent()
			switch e.Kind {
			case tls.QUICNoEvent:
				return nil
			case tls.QUICWriteData:
				if err := dst.HandleData(e.Level, e.Data); err != nil {
					return err
				}
			}
		}
	}
	for i := 0; i < 12; i++ {
		if err := pump(client, server); err != nil {
			t.Fatalf("server rejected handshake: %v", err)
		}
		if err := pump(server, client); err != nil {
			t.Fatalf("client rejected handshake: %v", err)
		}
		if client.ConnectionState().HandshakeComplete && server.ConnectionState().HandshakeComplete {
			t.Logf("QUIC-TLS composite handshake complete after %d rounds", i+1)
			return
		}
	}
	t.Fatal("handshake did not complete")
}

// TestCompositeTLSHandshake exercises a composite Ed25519+ML-DSA certificate over
// a plain crypto/tls connection (net.Pipe), isolating TLS behaviour from QUIC.
func TestCompositeTLSHandshake(t *testing.T) {
	cert, err := GenerateHybridCertificate(MLDSA65, "smoke", []string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	serverConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"smoke"},
	}
	clientConf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"smoke"},
		SignatureSchemes:   []tls.SignatureScheme{CompositeEd25519MLDSA65},
	}

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	srvErr := make(chan error, 1)
	go func() {
		conn := tls.Server(s, serverConf)
		if err := conn.Handshake(); err != nil {
			srvErr <- err
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			srvErr <- err
			return
		}
		_, err := conn.Write(buf)
		srvErr <- err
	}()

	client := tls.Client(c, clientConf)
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	t.Logf("client handshake OK; sig scheme verified, curve=%v", client.ConnectionState().CipherSuite)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if err := <-srvErr; err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("server: %v", err)
	}
	t.Log("composite TLS handshake + echo OK")
}
