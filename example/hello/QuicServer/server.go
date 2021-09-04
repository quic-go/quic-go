// This QUIC server will accept multiple client request simultaniously

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"

	quic "github.com/lucas-clemente/quic-go"
)

const Saddr = "0.0.0.0:4242"

func main() {
	log.Fatal(Server())
}

// Start a server 
func Server() error {
	listener, err := quic.ListenAddr(Saddr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			fmt.Println("Accept err", err)
			return err
		}
		go HandleStream(sess)
	}
}

func HandleStream(session quic.Session) {
	for {
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			fmt.Println("AcceptStream err", err)
			return
		}
		go func() {
			b := make([]byte, 1500)
			n, err := stream.Read(b)
			if err != nil {
				fmt.Println("Error in read", err)
			}

			fmt.Println("server Received ", string(b[:n]))
			_, err = stream.Write([]byte("Hey!!!"))
			if err != nil {
				log.Println("Stream write error: ", err)
			}
			return
		}()
	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"wq-vvv-01"},
	}
}
