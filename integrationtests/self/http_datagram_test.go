package self_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

func TestHTTPSettings(t *testing.T) {
	mux := http.NewServeMux()
	port := startHTTPServer(t, mux)

	t.Run("server settings", func(t *testing.T) {
		tlsConf := tlsClientConfigWithoutServerName.Clone()
		tlsConf.NextProtos = []string{http3.NextProtoH3}
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", port),
			tlsConf,
			getQuicConfig(nil),
		)
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		var tr http3.Transport
		cc := tr.NewClientConn(conn)

		select {
		case <-cc.ReceivedSettings():
		case <-time.After(time.Second):
			t.Fatal("didn't receive HTTP/3 settings")
		}

		settings := cc.Settings()
		require.True(t, settings.EnableExtendedConnect)
		require.False(t, settings.EnableDatagrams)
		require.Empty(t, settings.Other)
	})

	t.Run("client settings", func(t *testing.T) {
		connChan := make(chan http3.Connection, 1)
		mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
			conn := w.(http3.Hijacker).Connection()
			connChan <- conn
			w.WriteHeader(http.StatusOK)
		})

		tr := &http3.Transport{
			TLSClientConfig: getTLSClientConfigWithoutServerName(),
			QUICConfig: getQuicConfig(&quic.Config{
				MaxIdleTimeout:  10 * time.Second,
				EnableDatagrams: true,
			}),
			EnableDatagrams:    true,
			AdditionalSettings: map[uint64]uint64{1337: 42},
		}
		defer tr.Close()
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d/settings", port), nil)
		require.NoError(t, err)

		_, err = tr.RoundTrip(req)
		require.NoError(t, err)
		var conn http3.Connection
		select {
		case conn = <-connChan:
		case <-time.After(time.Second):
			t.Fatal("didn't receive HTTP/3 connection")
		}

		select {
		case <-conn.ReceivedSettings():
		case <-time.After(time.Second):
			t.Fatal("didn't receive HTTP/3 settings")
		}
		settings := conn.Settings()
		require.NotNil(t, settings)
		require.True(t, settings.EnableDatagrams)
		require.False(t, settings.EnableExtendedConnect)
		require.Equal(t, uint64(42), settings.Other[1337])
	})
}

func dialAndOpenHTTPDatagramStream(t *testing.T, addr string) http3.RequestStream {
	t.Helper()

	u, err := url.Parse(addr)
	require.NoError(t, err)

	tlsConf := getTLSClientConfigWithoutServerName()
	tlsConf.NextProtos = []string{http3.NextProtoH3}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, u.Host, tlsConf, getQuicConfig(&quic.Config{EnableDatagrams: true}))
	require.NoError(t, err)
	t.Cleanup(func() { conn.CloseWithError(0, "") })

	tr := http3.Transport{EnableDatagrams: true}
	t.Cleanup(func() { tr.Close() })
	cc := tr.NewClientConn(conn)
	t.Cleanup(func() { cc.CloseWithError(0, "") })
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	req := &http.Request{
		Method: http.MethodConnect,
		Proto:  "datagrams",
		Host:   u.Host,
		URL:    u,
	}
	require.NoError(t, str.SendRequestHeader(req))

	rsp, err := str.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	return str
}

func TestHTTPDatagrams(t *testing.T) {
	errChan := make(chan error, 1)
	const num = 5
	datagramChan := make(chan struct{}, num)
	mux := http.NewServeMux()
	mux.HandleFunc("/datagrams", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		conn := w.(http3.Hijacker).Connection()
		select {
		case <-conn.ReceivedSettings():
		case <-time.After(time.Second):
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !conn.Settings().EnableDatagrams {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)

		str := w.(http3.HTTPStreamer).HTTPStream()
		go str.Read([]byte{0}) // need to continue reading from stream to observe state transitions

		for {
			if _, err := str.ReceiveDatagram(context.Background()); err != nil {
				errChan <- err
				return
			}
			datagramChan <- struct{}{}
		}
	})

	port := startHTTPServer(t, mux, func(s *http3.Server) { s.EnableDatagrams = true })
	str := dialAndOpenHTTPDatagramStream(t, fmt.Sprintf("https://localhost:%d/datagrams", port))

	for i := 0; i < num; i++ {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(i))
		require.NoError(t, str.SendDatagram(bytes.Repeat(b, 100)))
	}
	var count int
loop:
	for {
		select {
		case <-datagramChan:
			count++
			if count >= num*4/5 {
				break loop
			}
		case err := <-errChan:
			t.Fatalf("receiving datagrams failed: %s", err)
		}
	}
	str.CancelWrite(42)

	select {
	case err := <-errChan:
		var serr *quic.StreamError
		require.ErrorAs(t, err, &serr)
		require.Equal(t, quic.StreamErrorCode(42), serr.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("didn't receive error")
	}
}

func TestHTTPDatagramClose(t *testing.T) {
	errChan := make(chan error, 1)
	datagramChan := make(chan []byte, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/datagrams", func(w http.ResponseWriter, r *http.Request) {
		conn := w.(http3.Hijacker).Connection()
		select {
		case <-conn.ReceivedSettings():
		case <-time.After(time.Second):
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !conn.Settings().EnableDatagrams {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)

		str := w.(http3.HTTPStreamer).HTTPStream()
		go str.Read([]byte{0}) // need to continue reading from stream to observe state transitions

		for {
			data, err := str.ReceiveDatagram(context.Background())
			if err != nil {
				errChan <- err
				return
			}
			datagramChan <- data
		}
	})

	port := startHTTPServer(t, mux, func(s *http3.Server) { s.EnableDatagrams = true })
	str := dialAndOpenHTTPDatagramStream(t, fmt.Sprintf("https://localhost:%d/datagrams", port))
	go str.Read([]byte{0})

	require.NoError(t, str.SendDatagram([]byte("foo")))
	select {
	case data := <-datagramChan:
		require.Equal(t, []byte("foo"), data)
	case <-time.After(time.Second):
		t.Fatal("didn't receive datagram")
	}
	// signal that we're done sending
	str.Close()

	var resetErr error
	select {
	case resetErr = <-errChan:
	case <-time.After(time.Second):
		t.Fatal("didn't receive error")
	}
	require.Equal(t, io.EOF, resetErr)

	// make sure we can't send anymore
	require.Error(t, str.SendDatagram([]byte("foo")))
}

func TestHTTPDatagramStreamReset(t *testing.T) {
	errChan := make(chan error, 1)
	datagramChan := make(chan []byte, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/datagrams", func(w http.ResponseWriter, r *http.Request) {
		conn := w.(http3.Hijacker).Connection()
		select {
		case <-conn.ReceivedSettings():
		case <-time.After(time.Second):
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !conn.Settings().EnableDatagrams {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)

		str := w.(http3.HTTPStreamer).HTTPStream()
		go str.Read([]byte{0}) // need to continue reading from stream to observe state transitions

		for {
			data, err := str.ReceiveDatagram(context.Background())
			if err != nil {
				errChan <- err
				return
			}
			str.CancelRead(42)
			datagramChan <- data
		}
	})

	port := startHTTPServer(t, mux, func(s *http3.Server) { s.EnableDatagrams = true })
	str := dialAndOpenHTTPDatagramStream(t, fmt.Sprintf("https://localhost:%d/datagrams", port))
	go str.Read([]byte{0})

	require.NoError(t, str.SendDatagram([]byte("foo")))
	select {
	case data := <-datagramChan:
		require.Equal(t, []byte("foo"), data)
	case <-time.After(time.Second):
		t.Fatal("didn't receive datagram")
	}

	var resetErr error
	select {
	case resetErr = <-errChan:
	case <-time.After(time.Second):
		t.Fatal("didn't receive error")
	}
	require.Equal(t, &quic.StreamError{ErrorCode: 42, Remote: false}, resetErr)

	var err error
	require.Eventually(t, func() bool {
		err = str.SendDatagram([]byte("foo"))
		return err != nil
	}, time.Second, 10*time.Millisecond)
	// make sure we can't send anymore
	require.Equal(t, &quic.StreamError{ErrorCode: 42, Remote: true}, err)
}
