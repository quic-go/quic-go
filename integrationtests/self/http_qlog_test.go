package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	h3qlog "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTP3Qlog(t *testing.T) {
	serverTrace := newMockTrace()
	clientTrace := newMockTrace()

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello, World!\n")
	})

	server := &http3.Server{
		Handler:   mux,
		TLSConfig: getTLSConfig(),
		QUICConfig: getQuicConfig(&quic.Config{
			Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
				return serverTrace
			},
		}),
	}

	conn := newUDPConnLocalhost(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Serve(conn)
	}()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	tr := &http3.Transport{
		TLSClientConfig: getTLSClientConfigWithoutServerName(),
		QUICConfig: getQuicConfig(&quic.Config{
			Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
				return clientTrace
			},
		}),
	}
	addDialCallback(t, tr)
	cl := &http.Client{Transport: tr}

	resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/hello", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "Hello, World!\n", string(body))
	resp.Body.Close()

	assert.Equal(t, 2, clientTrace.OpenRecorders())
	assert.Equal(t, 2, serverTrace.OpenRecorders())

	tr.Close()
	server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server didn't shut down")
	}

	// Recorders are closed in an AfterFunc, so we need to wait for them to be closed.
	assert.Eventually(t, func() bool { return clientTrace.OpenRecorders() == 0 }, time.Second, 10*time.Millisecond, "client recorders should be closed")
	assert.Eventually(t, func() bool { return serverTrace.OpenRecorders() == 0 }, time.Second, 10*time.Millisecond, "server recorders should be closed")
	assert.Equal(t, []string{h3qlog.EventSchema}, clientTrace.SchemasChecked)
	assert.Equal(t, []string{h3qlog.EventSchema}, serverTrace.SchemasChecked)
}
