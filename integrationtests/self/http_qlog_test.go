package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	h3qlog "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

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

func TestHTTP3QlogHeaderRedaction(t *testing.T) {
	var serverEvents, clientEvents events.Recorder
	redact := func(name, value string) string {
		switch name {
		case ":path":
			u, err := url.ParseRequestURI(value)
			require.NoError(t, err)
			query := u.Query()
			query.Set("token", "***")
			u.RawQuery = query.Encode()
			return u.RequestURI()
		case "Authorization", "Set-Cookie", "X-Secret":
			return "***"
		default:
			return value
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		assert.NoError(t, err)
		assert.Equal(t, "secret", r.URL.Query().Get("token"))
		assert.Equal(t, "request secret", r.Header.Get("Authorization"))
		assert.Equal(t, "request trailer secret", r.Trailer.Get("X-Secret"))
		w.Header().Set("Set-Cookie", "response secret")
		w.Header().Set("X-Public", "public")
		w.Header().Set("Trailer", "X-Secret")
		io.WriteString(w, "response body")
		w.Header().Set("X-Secret", "response trailer secret")
	})
	port := startHTTPServer(t, mux, func(s *http3.Server) {
		s.QUICConfig.Tracer = h3qlog.RedactHeaders(newTracer(&serverEvents), redact)
	})
	cl := newHTTP3Client(t, func(tr *http3.Transport) {
		tr.QUICConfig.Tracer = h3qlog.RedactHeaders(newTracer(&clientEvents), redact)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://localhost:%d/headers?format=json&token=secret", port), strings.NewReader("request body"))
	require.NoError(t, err)
	req.Header.Set("Authorization", "request secret")
	req.Header.Set("X-Public", "public")
	req.Trailer = http.Header{"X-Secret": {"request trailer secret"}}
	resp, err := cl.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, "response secret", resp.Header.Get("Set-Cookie"))
	require.Equal(t, "response trailer secret", resp.Trailer.Get("X-Secret"))

	for _, recorder := range []*events.Recorder{&serverEvents, &clientEvents} {
		fields := make(map[string][]string)
		for _, ev := range recorder.Events(h3qlog.FrameCreated{}, h3qlog.FrameParsed{}) {
			var frame h3qlog.Frame
			switch e := ev.(type) {
			case h3qlog.FrameCreated:
				frame = e.Frame
			case h3qlog.FrameParsed:
				frame = e.Frame
			}
			if hf, ok := frame.Frame.(h3qlog.HeadersFrame); ok {
				for _, f := range hf.HeaderFields {
					fields[f.Name] = append(fields[f.Name], f.Value)
				}
			}
		}
		require.Equal(t, []string{"***"}, fields["authorization"])
		require.Equal(t, []string{"***"}, fields["set-cookie"])
		require.Equal(t, []string{"***", "***"}, fields["x-secret"])
		require.Equal(t, []string{"public", "public"}, fields["x-public"])
		require.Equal(t, []string{"/headers?format=json&token=%2A%2A%2A"}, fields[":path"])
		require.Equal(t, []string{"200"}, fields[":status"])
	}
}
