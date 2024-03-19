package main

// https://fossies.org/linux/quic-go/example/echo/echo.go
// if error:
// sudo sysctl -w net.core.rmem_max=2500000
// sudo sysctl -w net.core.wmem_max=2500000

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"

	"github.com/danielpfeifer02/quic-go-prio-packs"
)

const addr = "localhost:4242"

const message = "foobar"

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	go func() { log.Fatal(echoServer()) }()

	err := clientMain()
	if err != nil {
		panic(err)
	}
}

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), generateQUICConfig())
	if err != nil {
		return err
	}
	defer listener.Close()

	// Accept the incoming connection from the client
	conn, err := listener.Accept(context.Background())
	if err != nil {
		return err
	}

	// // Accept the first stream opened by the client
	// stream, err := conn.AcceptStream(context.Background())
	// if err != nil {
	// 	panic(err)
	// }
	// defer stream.Close()

	// // TODO: AcceptStream seems to not return the stream with the same priority?
	// // fmt.Printf("Prio stream one (serverside): %d\n", stream.Priority())

	// // Handle the first stream opened by the client
	// // in a separate goroutine
	// go func(stream quic.Stream) {
	// 	// Echo through the loggingWriter
	// 	_, err = io.Copy(loggingWriter{stream}, stream)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }(stream)

	// Accept the second stream opened by the client
	stream2, err2 := conn.AcceptStream(context.Background())
	if err2 != nil {
		panic(err2)
	}
	defer stream2.Close()

	// fmt.Printf("Prio stream two (serverside): %d\n", stream2.Priority())

	// Handle the second stream opened by the client
	// in the current goroutine
	// Echo through the loggingWriter
	_, err = io.Copy(loggingWriter{stream2}, stream2)
	if err != nil {
		panic(err)
	}

	return nil
}

func clientMain() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	conn, err := quic.DialAddr(context.Background(), addr, tlsConf, generateQUICConfig())
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")

	// Open a new stream with high priority
	stream_high_prio, err := conn.OpenStreamSyncWithPriority(context.Background(), quic.HighPriority)
	if err != nil {
		return err
	}
	defer stream_high_prio.Close()
	// fmt.Printf("Prio of stream one (clientside): %d\n", stream_high_prio.Priority())

	// Open a new stream with low priority
	// stream_low_prio, err := conn.OpenStreamSyncWithPriority(context.Background(), quic.LowPriority)
	// if err != nil {
	// 	return err
	// }
	// defer stream_low_prio.Close()
	// fmt.Printf("Prio of stream two (clientside): %d\n", stream_low_prio.Priority())

	// Send three messages with high priority
	for i := 0; i < 3; i++ {

		fmt.Printf("	>>Client: Sending with high prio '%s%d'\n", message, i)
		_, err = stream_high_prio.Write([]byte(message + fmt.Sprintf("%d", i)))
		if err != nil {
			return err
		}

		buf_high := make([]byte, len(message)+1)
		_, err = io.ReadFull(stream_high_prio, buf_high)
		if err != nil {
			return err
		}
		fmt.Printf("	>>Client: Got with high prio '%s'\n\n", buf_high)

	}

	// // Send three messages with low priority
	// for i := 0; i < 3; i++ {

	// 	fmt.Printf("	>>Client: Sending with low prio '%s%d'\n", message, i+3)
	// 	_, err = stream_low_prio.Write([]byte(message + fmt.Sprintf("%d", i+3)))
	// 	if err != nil {
	// 		return err
	// 	}

	// 	buf_low := make([]byte, len(message)+1)
	// 	_, err = io.ReadFull(stream_low_prio, buf_low)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	fmt.Printf("	>>Client: Got with low prio '%s'\n\n", buf_low)

	// }

	return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("	>>Server: Got '%s'\n	>>Server: Echoing on same stream\n", string(b))
	return w.Writer.Write(b)
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

	// Create a KeyLogWriter
	keyLogFile, err := os.OpenFile("tls.keylog", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	// defer keyLogFile.Close() // TODO why not close?

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
		KeyLogWriter: keyLogFile,
		CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
	}
}

func generateQUICConfig() *quic.Config {
	return &quic.Config{}
}
