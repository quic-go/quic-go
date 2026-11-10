package self_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPResponseContentLength compares how the standard library's HTTP/1.1 and HTTP/2 implementations
// and quic-go's HTTP/3 implementation handle the Content-Length of responses.
func TestHTTPResponseContentLength(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		handler   http.HandlerFunc
		skipHTTP2 bool
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
		},
		{
			name:   "response longer than Content-Length of 0",
			method: http.MethodGet,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "0")
				w.(http.Flusher).Flush()
				io.WriteString(w, "foobar")
			},
			// the HTTP/2 server doesn't enforce a Content-Length of 0: https://github.com/golang/go/issues/56019
			skipHTTP2: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			do := func(t *testing.T, cl *http.Client, url string) (*http.Response, []byte, error) {
				req, err := http.NewRequest(tc.method, url, nil)
				require.NoError(t, err)
				resp, err := cl.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				return resp, body, err
			}

			// The HTTP/1.1 and HTTP/2 servers use real sockets, so only HTTP/3 runs in a bubble.
			var h3Resp *http.Response
			var h3Body []byte
			var h3Err error
			synctest.Test(t, func(t *testing.T) {
				n := newTestNetwork(t)
				mux := http.NewServeMux()
				mux.Handle("/", tc.handler)
				port := startHTTPServer(t, n.NewConn(), mux)
				h3Resp, h3Body, h3Err = do(t, newHTTP3Client(t, n), fmt.Sprintf("https://localhost:%d", port))
			})

			for _, h2 := range []bool{false, true} {
				if h2 && tc.skipHTTP2 {
					continue
				}
				s := httptest.NewUnstartedServer(tc.handler)
				s.EnableHTTP2 = h2
				s.StartTLS()
				t.Cleanup(s.Close)
				resp, body, err := do(t, s.Client(), s.URL)

				assert.Equal(t, resp.StatusCode, h3Resp.StatusCode, resp.Proto)
				assert.Equal(t, resp.Header["Content-Length"], h3Resp.Header["Content-Length"], resp.Proto)
				assert.Equal(t, resp.ContentLength, h3Resp.ContentLength, resp.Proto)
				assert.Equal(t, body, h3Body, resp.Proto)
				assert.Equal(t, err != nil, h3Err != nil, "%s: %v, HTTP/3: %v", resp.Proto, err, h3Err)
			}
		})
	}
}
