package self_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPResponseContentLength compares how the standard library's HTTP/2 implementation
// and quic-go's HTTP/3 implementation handle the Content-Length of responses.
func TestHTTPResponseContentLength(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		handler http.HandlerFunc
		skip    string
	}{
		{
			name:   "response with Content-Length",
			method: http.MethodGet,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "6")
				io.WriteString(w, "foobar")
			},
		},
		{
			name:    "response without Content-Length",
			method:  http.MethodGet,
			handler: func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "foobar") },
		},
		{
			name:   "flushed response",
			method: http.MethodGet,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				io.WriteString(w, "foo")
				w.(http.Flusher).Flush()
				io.WriteString(w, "bar")
			},
		},
		{
			name:    "HEAD response",
			method:  http.MethodHead,
			handler: func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "foobar") },
		},
		{
			name:    "HEAD response with Content-Length",
			method:  http.MethodHead,
			handler: func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Content-Length", "6") },
		},
		{
			name:    "204 response",
			method:  http.MethodGet,
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) },
		},
		{
			name:    "empty response after 103",
			method:  http.MethodGet,
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusEarlyHints) },
		},
		{
			name:   "response shorter than Content-Length",
			method: http.MethodGet,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "6")
				io.WriteString(w, "foo")
			},
			skip: "https://github.com/quic-go/quic-go/pull/5913",
		},
		{
			name:   "response longer than Content-Length",
			method: http.MethodGet,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "3")
				// the HTTP/2 server only enforces the Content-Length after sending the header
				w.(http.Flusher).Flush()
				io.WriteString(w, "foobar")
			},
			skip: "https://github.com/quic-go/quic-go/pull/5913",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}

			do := func(cl *http.Client, url string) (*http.Response, []byte, error) {
				req, err := http.NewRequest(tc.method, url, nil)
				require.NoError(t, err)
				resp, err := cl.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				return resp, body, err
			}

			h2Server := httptest.NewUnstartedServer(tc.handler)
			h2Server.EnableHTTP2 = true
			h2Server.StartTLS()
			t.Cleanup(h2Server.Close)
			h2Resp, h2Body, h2Err := do(h2Server.Client(), h2Server.URL)

			mux := http.NewServeMux()
			mux.Handle("/", tc.handler)
			port := startHTTPServer(t, mux)
			h3Resp, h3Body, h3Err := do(newHTTP3Client(t), fmt.Sprintf("https://localhost:%d", port))

			assert.Equal(t, h2Resp.StatusCode, h3Resp.StatusCode)
			assert.Equal(t, h2Resp.Header["Content-Length"], h3Resp.Header["Content-Length"])
			assert.Equal(t, h2Resp.ContentLength, h3Resp.ContentLength)
			assert.Equal(t, h2Body, h3Body)
			assert.Equal(t, h2Err != nil, h3Err != nil, "HTTP/2: %v, HTTP/3: %v", h2Err, h3Err)
		})
	}
}
