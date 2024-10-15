package quic_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/internal/protocol"
)

type chanBackedStream struct {
	toRemote   chan<- []byte
	fromRemote <-chan []byte
	buf        []byte
}

// Read implements io.ReadWriter.
func (c *chanBackedStream) Read(p []byte) (n int, err error) {
	var b []byte
	if c.buf != nil {
		b = c.buf
		c.buf = nil
	} else {
		var ok bool
		b, ok = <-c.fromRemote
		if !ok {
			return 0, io.EOF
		}
	}
	if len(b) < len(p) {
		copy(p, b)
		return len(b), nil
	}

	copy(p, b[:len(p)])
	c.buf = b[len(p):]
	return len(p), nil
}

// Write implements io.ReadWriter.
func (c *chanBackedStream) Write(p []byte) (n int, err error) {
	cloned := make([]byte, len(p))
	copy(cloned, p)
	c.toRemote <- cloned
	return len(p), nil
}

func (c *chanBackedStream) Close() error {
	return nil
}

func newPair() (*chanBackedStream, *chanBackedStream) {
	atob := make(chan []byte, 1024)
	btoa := make(chan []byte, 1024)
	a := &chanBackedStream{
		toRemote:   atob,
		fromRemote: btoa,
	}
	b := &chanBackedStream{
		toRemote:   btoa,
		fromRemote: atob,
	}
	return a, b
}

func TestQoSH3(t *testing.T) {
	atob, btoa := newPair()

	server := http3.Server{}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("server got request")
		w.Write([]byte("hello"))
	})
	waitForServer := make(chan struct{})
	go func() {
		close(waitForServer)
		c, err := quic.NewQoSConn(btoa, &tls.Config{InsecureSkipVerify: true}, quic.PopulateConfigWithDefaults(nil), protocol.PerspectiveServer)
		if err != nil {
			fmt.Println("server err", err)
			t.Fail()
			return
		}
		err = server.ServeQUICConn(c)
		if err != nil {
			fmt.Println("server serve err", err)
			t.Fail()
		}
	}()

	clientRT := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{}, // set a TLS client config, if desired
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			clientConn, err := quic.NewQoSConn(atob, &tls.Config{InsecureSkipVerify: true}, quic.PopulateConfigWithDefaults(nil), protocol.PerspectiveClient)
			if err != nil {
				return nil, err
			}
			return clientConn, nil
		},
	}
	client := &http.Client{
		Transport: clientRT,
	}
	resp, err := client.Get("https://www.example.com/")
	if err != nil {
		fmt.Println("client get err", err)
		t.Fail()
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("client get err", err)
		t.Fail()
	}

	if string(respBody) != "hello" {
		fmt.Println("client get err", err)
		t.Fail()
	}

	<-waitForServer
}

func TestQoSH3h2o(t *testing.T) {
	t.Skip("Requires h2o to be running")
	h2oEndpoint := "31.133.134.206:8443"

	f, err := os.OpenFile("/tmp/keys", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Don't verify server certificate (not recommended for production)
		NextProtos:         []string{"h3"},
		KeyLogWriter:       f,
	}

	conn, err := tls.Dial("tcp", h2oEndpoint, tlsConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	c, err := quic.NewQoSConn(conn, tlsConfig, quic.PopulateConfigWithDefaults(nil), protocol.PerspectiveClient)
	if err != nil {
		t.Fatalf("Failed to create QoS connection: %v", err)
	}

	clientRT := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{}, // set a TLS client config, if desired
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			return c, nil
		},
	}
	client := &http.Client{
		Transport: clientRT,
	}
	resp, err := client.Get("https://www.example.com/file/src/main.c")
	if err != nil {
		fmt.Println("client get err", err)
		t.Fail()
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("client get err", err)
		t.Fail()
	}
	fmt.Println("Status code", resp.StatusCode)
	fmt.Println("Body", string(respBody))

}
