package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"testing"

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

var _ io.ReadWriter = &chanBackedStream{}

func TestPair(t *testing.T) {
	atob, btoa := newPair()

	go func() {
		atob.Write([]byte("hello"))
	}()
	out := make([]byte, 1024)
	n, err := btoa.Read(out)
	if !(err == nil && n == 5 && string(out[:n]) == "hello") {
		t.Fatal("failed")
	}
}

func TestQoS(t *testing.T) {
	atob, btoa := newPair()

	waitForServer := make(chan struct{})
	go func() {
		defer close(waitForServer)
		conn, err := NewQoSConn(btoa, &tls.Config{InsecureSkipVerify: true}, populateConfig(nil), protocol.PerspectiveServer)
		if err != nil {
			fmt.Println("server err", err)
			t.Fail()
			return
		}

		s, err := conn.AcceptStream(context.Background())
		if err != nil {
			fmt.Println("server stream err", err)
			t.Fail()
		}
		defer s.Close()
		buf := make([]byte, 1024)
		n, err := s.Read(buf)
		if err != nil && err != io.EOF {
			fmt.Println("server read err", err)
			t.Fail()
		}

		res := buf[:n]
		if string(res) != "hello" {
			fmt.Println("server read wrong data", string(res))
			t.Fail()
		}

		_, err = s.Write(res)
		if err != nil {
			fmt.Println("server write err", err)
			t.Fail()
		}
	}()

	clientConn, err := NewQoSConn(atob, &tls.Config{InsecureSkipVerify: true}, populateConfig(nil), protocol.PerspectiveClient)
	if err != nil {
		t.Fatal(err)
	}

	s, err := clientConn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := s.Read(buf)
	res := buf[:n]
	if err != nil && err != io.EOF {
		t.Fatalf("client read err: %v", err)
	}
	if string(res) != "hello" {
		t.Fatalf("client read wrong data: %s", string(res))
	}

	err = s.Close()
	if err != nil {
		t.Fatal(err)
	}
	<-waitForServer
}
