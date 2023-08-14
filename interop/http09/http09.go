//go:build !utls

package http09

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"

	"github.com/quic-go/quic-go"
)

type responseWriter struct {
	io.Writer
	headers http.Header
}

var _ http.ResponseWriter = &responseWriter{}

func (w *responseWriter) Header() http.Header {
	if w.headers == nil {
		w.headers = make(http.Header)
	}
	return w.headers
}

func (w *responseWriter) WriteHeader(int) {}

// Server is a HTTP/0.9 server listening for QUIC connections.
type Server struct {
	*http.Server

	QuicConfig *quic.Config

	mutex    sync.Mutex
	listener *quic.EarlyListener
}

func (s *Server) handleStream(str quic.Stream) error {
	reqBytes, err := io.ReadAll(str)
	if err != nil {
		return err
	}
	request := string(reqBytes)
	request = strings.TrimRight(request, "\r\n")
	request = strings.TrimRight(request, " ")

	log.Printf("Received request: %s\n", request)

	if request[:5] != "GET /" {
		str.CancelWrite(42)
		return nil
	}

	u, err := url.Parse(request[4:])
	if err != nil {
		return err
	}
	u.Scheme = "https"

	req := &http.Request{
		Method:     http.MethodGet,
		Proto:      "HTTP/0.9",
		ProtoMajor: 0,
		ProtoMinor: 9,
		Body:       str,
		URL:        u,
	}

	handler := s.Handler
	if handler == nil {
		handler = http.DefaultServeMux
	}

	var panicked bool
	func() {
		defer func() {
			if p := recover(); p != nil {
				// Copied from net/http/server.go
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				log.Printf("http: panic serving: %v\n%s", p, buf)
				panicked = true
			}
		}()
		handler.ServeHTTP(&responseWriter{Writer: str}, req)
	}()

	if panicked {
		if _, err := str.Write([]byte("500")); err != nil {
			return err
		}
	}
	return str.Close()
}
