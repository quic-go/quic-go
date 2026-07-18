package self_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

func TestHTTPOverQMux(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConf := getTLSConfig()
	tlsConf.NextProtos = []string{http3.NextProtoH3}
	clientTLSConf := getTLSClientConfig()
	clientTLSConf.NextProtos = []string{http3.NextProtoH3}

	serverConnChan := make(chan struct {
		conn *quic.Conn
		err  error
	}, 1)
	go func() {
		conn, err := quic.AcceptQMux(ctx, serverPipe, tlsConf, getQuicConfig(nil))
		serverConnChan <- struct {
			conn *quic.Conn
			err  error
		}{conn: conn, err: err}
	}()
	clientConn, err := quic.DialQMux(ctx, clientPipe, clientTLSConf, getQuicConfig(nil))
	require.NoError(t, err)
	serverResult := <-serverConnChan
	require.NoError(t, serverResult.err)
	serverConn := serverResult.conn

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		_, err = w.Write([]byte("hello over qmux: " + string(body)))
		require.NoError(t, err)
	})
	server := &http3.Server{
		TLSConfig:  tlsConf,
		QUICConfig: getQuicConfig(nil),
		Handler:    mux,
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ServeQUICConn(serverConn) }()

	client := (&http3.Transport{}).NewClientConn(clientConn)
	select {
	case <-client.ReceivedSettings():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for HTTP/3 settings over QMux")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://localhost/hello", strings.NewReader("request body"))
	require.NoError(t, err)
	rsp, err := client.RoundTrip(req)
	require.NoError(t, err)
	defer rsp.Body.Close()
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	body, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello over qmux: request body", string(body))

	require.NoError(t, clientConn.CloseWithError(0, ""))
	select {
	case <-serverErr:
	case <-time.After(time.Second):
		t.Fatal("server didn't stop after closing QMux client connection")
	}
}
