package self_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	"github.com/stretchr/testify/require"
)

type neverEnding byte

func (b neverEnding) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

func randomString(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n := mrand.Intn(len(alphabet))
		b[i] = alphabet[n]
	}
	return string(b)
}

func startHTTPServer(t *testing.T, mux *http.ServeMux, opts ...func(*http3.Server)) (port int) {
	t.Helper()
	server := &http3.Server{
		Handler:    mux,
		TLSConfig:  getTLSConfig(),
		QUICConfig: getQuicConfig(&quic.Config{Allow0RTT: true, EnableDatagrams: true}),
	}
	for _, opt := range opts {
		opt(server)
	}

	conn := newUPDConnLocalhost(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Serve(conn)
	}()

	t.Cleanup(func() {
		conn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("server didn't shut down")
		}
	})
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func newHTTP3Client(t *testing.T) *http.Client {
	tr := &http3.Transport{
		TLSClientConfig:    getTLSClientConfigWithoutServerName(),
		QUICConfig:         getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
		DisableCompression: true,
	}
	t.Cleanup(func() { tr.Close() })
	return &http.Client{Transport: tr}
}

func TestHTTPGet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello, World!\n")
	})
	mux.HandleFunc("/long", func(w http.ResponseWriter, r *http.Request) {
		w.Write(PRDataLong)
	})
	port := startHTTPServer(t, mux)

	cl := newHTTP3Client(t)

	t.Run("small", func(t *testing.T) {
		resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/hello", port))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(&readerWithTimeout{Reader: resp.Body, Timeout: 2 * time.Second})
		require.NoError(t, err)
		require.Equal(t, "Hello, World!\n", string(body))
	})

	t.Run("big", func(t *testing.T) {
		resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/long", port))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(&readerWithTimeout{Reader: resp.Body, Timeout: 10 * time.Second})
		require.NoError(t, err)
		require.Equal(t, PRDataLong, body)
	})
}

func TestHTTPPost(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
	})
	port := startHTTPServer(t, mux)

	cl := newHTTP3Client(t)

	t.Run("small", func(t *testing.T) {
		resp, err := cl.Post(
			fmt.Sprintf("https://localhost:%d/echo", port),
			"text/plain",
			bytes.NewReader([]byte("Hello, world!")),
		)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(&readerWithTimeout{Reader: resp.Body, Timeout: 2 * time.Second})
		require.NoError(t, err)
		require.Equal(t, []byte("Hello, world!"), body)
	})

	t.Run("big", func(t *testing.T) {
		resp, err := cl.Post(
			fmt.Sprintf("https://localhost:%d/echo", port),
			"text/plain",
			bytes.NewReader(PRData),
		)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(&readerWithTimeout{Reader: resp.Body, Timeout: 10 * time.Second})
		require.NoError(t, err)
		require.Equal(t, PRData, body)
	})
}

func TestHTTPMultipleRequests(t *testing.T) {
	mux := http.NewServeMux()
	port := startHTTPServer(t, mux)

	t.Run("reading the response", func(t *testing.T) {
		mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "Hello, World!\n")
		})

		cl := newHTTP3Client(t)
		var eg errgroup.Group
		for i := 0; i < 200; i++ {
			eg.Go(func() error {
				resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/hello", port))
				if err != nil {
					return err
				}
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
				}
				body, err := io.ReadAll(&readerWithTimeout{Reader: resp.Body, Timeout: 3 * time.Second})
				if err != nil {
					return err
				}
				if string(body) != "Hello, World!\n" {
					return fmt.Errorf("unexpected body: %q", body)
				}
				return nil
			})
		}
		require.NoError(t, eg.Wait())
	})

	t.Run("not reading the response", func(t *testing.T) {
		mux.HandleFunc("/prdata", func(w http.ResponseWriter, r *http.Request) {
			w.Write(PRData)
		})

		cl := newHTTP3Client(t)
		const num = 150

		for i := 0; i < num; i++ {
			resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/prdata", port))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.NoError(t, resp.Body.Close())
		}
	})
}

func TestContentLengthForSmallResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/small", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("foo"))
		w.Write([]byte("bar"))
	})
	port := startHTTPServer(t, mux)

	resp, err := newHTTP3Client(t).Get(fmt.Sprintf("https://localhost:%d/small", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "6", resp.Header.Get("Content-Length"))
}

func TestHTTPHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/headers/response", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("foo", "bar")
		w.Header().Set("lorem", "ipsum")
		w.Header().Set("echo", r.Header.Get("echo"))
	})
	port := startHTTPServer(t, mux)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d/headers/response", port), nil)
	require.NoError(t, err)
	echoHdr := randomString(128)
	req.Header.Set("echo", echoHdr)

	resp, err := newHTTP3Client(t).Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "bar", resp.Header.Get("foo"))
	require.Equal(t, "ipsum", resp.Header.Get("lorem"))
	require.Equal(t, echoHdr, resp.Header.Get("echo"))
}

func TestHTTPTrailers(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/trailers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "AtEnd1, AtEnd2")
		w.Header().Add("Trailer", "Never")
		w.Header().Add("Trailer", "LAST")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
		w.WriteHeader(http.StatusOK)
		w.Header().Set("AtEnd1", "value 1")
		io.WriteString(w, "This HTTP response has both headers before this text and trailers at the end.\n")
		w.(http.Flusher).Flush()
		w.Header().Set("AtEnd2", "value 2")
		io.WriteString(w, "More text\n")
		w.(http.Flusher).Flush()
		w.Header().Set("LAST", "value 3")
		w.Header().Set(http.TrailerPrefix+"Unannounced", "Surprise!")
		w.Header().Set("Late-Header", "No surprise!")
	})

	port := startHTTPServer(t, mux)

	resp, err := newHTTP3Client(t).Get(fmt.Sprintf("https://localhost:%d/trailers", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Trailer"))
	require.NotContains(t, resp.Header, "Atend1")
	require.NotContains(t, resp.Header, "Atend2")
	require.NotContains(t, resp.Header, "Never")
	require.NotContains(t, resp.Header, "Last")
	require.NotContains(t, resp.Header, "Late-Header")
	require.Equal(t, http.Header(map[string][]string{
		"Atend1": nil,
		"Atend2": nil,
		"Never":  nil,
		"Last":   nil,
	}), resp.Trailer)

	body, err := io.ReadAll(&readerWithTimeout{Reader: resp.Body, Timeout: 3 * time.Second})
	require.NoError(t, err)
	require.Equal(t, "This HTTP response has both headers before this text and trailers at the end.\nMore text\n", string(body))
	for k := range resp.Header {
		require.NotContains(t, k, http.TrailerPrefix)
	}
	require.Equal(t, http.Header(map[string][]string{
		"Atend1":      {"value 1"},
		"Atend2":      {"value 2"},
		"Last":        {"value 3"},
		"Unannounced": {"Surprise!"},
	}), resp.Trailer)
}

func TestHTTPErrAbortHandler(t *testing.T) {
	respChan := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/abort", func(w http.ResponseWriter, r *http.Request) {
		// no recover here as it will interfere with the handler
		w.Write([]byte("foobar"))
		w.(http.Flusher).Flush()
		// wait for the client to receive the response
		<-respChan
		panic(http.ErrAbortHandler)
	})
	port := startHTTPServer(t, mux)

	resp, err := newHTTP3Client(t).Get(fmt.Sprintf("https://localhost:%d/abort", port))
	close(respChan)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.Error(t, err)
	var h3Err *http3.Error
	require.True(t, errors.As(err, &h3Err))
	require.Equal(t, http3.ErrCodeInternalError, h3Err.ErrorCode)
	// the body will be a prefix of what's written
	require.True(t, bytes.HasPrefix([]byte("foobar"), body))
}

func TestHTTPGzip(t *testing.T) {
	mux := http.NewServeMux()
	var acceptEncoding string
	mux.HandleFunc("/hellogz", func(w http.ResponseWriter, r *http.Request) {
		acceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("foo", "bar")

		gw := gzip.NewWriter(w)
		defer gw.Close()
		_, err := gw.Write([]byte("Hello, World!\n"))
		require.NoError(t, err)
	})
	port := startHTTPServer(t, mux)

	cl := newHTTP3Client(t)
	cl.Transport.(*http3.Transport).DisableCompression = false
	resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/hellogz", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.True(t, resp.Uncompressed)

	body, err := io.ReadAll(&readerWithTimeout{Reader: resp.Body, Timeout: 3 * time.Second})
	require.NoError(t, err)
	require.Equal(t, "Hello, World!\n", string(body))

	// make sure the server received the Accept-Encoding header
	require.Equal(t, "gzip", acceptEncoding)
}

func TestHTTPDifferentOrigins(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/remote-addr", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RemoteAddr", r.RemoteAddr)
		w.WriteHeader(http.StatusOK)
	})
	port := startHTTPServer(t, mux)

	cl := newHTTP3Client(t)
	resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/remote-addr", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	addr1 := resp.Header.Get("X-RemoteAddr")
	require.NotEmpty(t, addr1)
	resp, err = cl.Get(fmt.Sprintf("https://127.0.0.1:%d/remote-addr", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	addr2 := resp.Header.Get("X-RemoteAddr")
	require.NotEmpty(t, addr2)
	require.Equal(t, addr1, addr2)
}

func TestHTTPServerIdleTimeout(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello, World!\n")
	})
	port := startHTTPServer(t, mux, func(s *http3.Server) { s.IdleTimeout = 100 * time.Millisecond })

	cl := newHTTP3Client(t)
	_, err := cl.Get(fmt.Sprintf("https://localhost:%d/hello", port))
	require.NoError(t, err)

	time.Sleep(150 * time.Millisecond)

	_, err = cl.Get(fmt.Sprintf("https://localhost:%d/hello", port))
	require.Error(t, err)
	var appErr *quic.ApplicationError
	require.ErrorAs(t, err, &appErr)
	require.Equal(t, quic.ApplicationErrorCode(http3.ErrCodeNoError), appErr.ErrorCode)
}

func TestHTTPReestablishConnectionAfterDialError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello, World!\n")
	})
	port := startHTTPServer(t, mux)

	var dialCounter int
	testErr := errors.New("test error")
	cl := http.Client{
		Transport: &http3.Transport{
			TLSClientConfig: getTLSClientConfig(),
			Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (quic.EarlyConnection, error) {
				dialCounter++
				if dialCounter == 1 { // make the first dial fail
					return nil, testErr
				}
				return quic.DialAddrEarly(ctx, addr, tlsConf, conf)
			},
		},
	}
	defer cl.Transport.(io.Closer).Close()

	_, err := cl.Get(fmt.Sprintf("https://localhost:%d/hello", port))
	require.ErrorIs(t, err, testErr)
	resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/hello", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHTTPClientRequestContextCancellation(t *testing.T) {
	mux := http.NewServeMux()
	port := startHTTPServer(t, mux)
	cl := newHTTP3Client(t)

	t.Run("before response", func(t *testing.T) {
		mux.HandleFunc("/cancel-before", func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		})

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/cancel-before", port), nil)
		require.NoError(t, err)
		_, err = cl.Do(req)
		require.Error(t, err)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("after response", func(t *testing.T) {
		errChan := make(chan error, 1)
		mux.HandleFunc("/cancel-after", func(w http.ResponseWriter, r *http.Request) {
			// TODO(#4508): check for request context cancellations
			for {
				if _, err := w.Write([]byte("foobar")); err != nil {
					errChan <- err
					return
				}
			}
		})

		ctx, cancel := context.WithCancel(context.Background())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/cancel-after", port), nil)
		require.NoError(t, err)
		resp, err := cl.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		cancel()

		select {
		case err := <-errChan:
			require.Error(t, err)
			var http3Err *http3.Error
			require.True(t, errors.As(err, &http3Err))
			require.Equal(t, http3.ErrCodeRequestCanceled, http3Err.ErrorCode)
			require.True(t, http3Err.Remote)
		case <-time.After(time.Second):
			t.Fatal("handler was not called")
		}

		_, err = resp.Body.Read([]byte{0})
		var http3Err *http3.Error
		require.True(t, errors.As(err, &http3Err))
		require.Equal(t, http3.ErrCodeRequestCanceled, http3Err.ErrorCode)
		require.False(t, http3Err.Remote)
	})
}

func TestHTTPDeadlines(t *testing.T) {
	const deadlineDelay = 50 * time.Millisecond

	mux := http.NewServeMux()
	port := startHTTPServer(t, mux)
	cl := newHTTP3Client(t)

	t.Run("read deadline", func(t *testing.T) {
		type result struct {
			body []byte
			err  error
		}

		resultChan := make(chan result, 1)
		mux.HandleFunc("/read-deadline", func(w http.ResponseWriter, r *http.Request) {
			rc := http.NewResponseController(w)
			require.NoError(t, rc.SetReadDeadline(time.Now().Add(deadlineDelay)))
			body, err := io.ReadAll(r.Body)
			resultChan <- result{body: body, err: err}
			w.Write([]byte("ok"))
		})

		expectedEnd := time.Now().Add(deadlineDelay)
		resp, err := cl.Post(
			fmt.Sprintf("https://localhost:%d/read-deadline", port),
			"text/plain",
			neverEnding('a'),
		)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(&readerWithTimeout{Reader: resp.Body, Timeout: 2 * deadlineDelay})
		require.NoError(t, err)
		require.True(t, time.Now().After(expectedEnd))
		require.Equal(t, "ok", string(body))

		select {
		case result := <-resultChan:
			require.ErrorIs(t, result.err, os.ErrDeadlineExceeded)
			require.Contains(t, string(result.body), "aa")
		default:
			t.Fatal("handler was not called")
		}
	})

	t.Run("write deadline", func(t *testing.T) {
		errChan := make(chan error, 1)
		mux.HandleFunc("/write-deadline", func(w http.ResponseWriter, r *http.Request) {
			rc := http.NewResponseController(w)
			require.NoError(t, rc.SetWriteDeadline(time.Now().Add(deadlineDelay)))

			_, err := io.Copy(w, neverEnding('a'))
			errChan <- err
		})

		expectedEnd := time.Now().Add(deadlineDelay)

		resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/write-deadline", port))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(&readerWithTimeout{Reader: resp.Body, Timeout: 2 * deadlineDelay})
		require.NoError(t, err)
		require.True(t, time.Now().After(expectedEnd))
		require.Contains(t, string(body), "aa")

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		case <-time.After(2 * deadlineDelay):
			t.Fatal("handler was not called")
		}
	})
}

func TestHTTPServeQUICConn(t *testing.T) {
	tlsConf := getTLSConfig()
	tlsConf.NextProtos = []string{http3.NextProtoH3}
	ln, err := quic.Listen(newUPDConnLocalhost(t), tlsConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello, World!\n")
	})
	server := &http3.Server{
		TLSConfig:  tlsConf,
		QUICConfig: getQuicConfig(nil),
		Handler:    mux,
	}
	errChan := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			errChan <- fmt.Errorf("failed to accept QUIC connection: %w", err)
			return
		}
		errChan <- server.ServeQUICConn(conn) // returns once the client closes
	}()

	cl := newHTTP3Client(t)
	resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/hello", ln.Addr().(*net.UDPAddr).Port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.NoError(t, cl.Transport.(io.Closer).Close())
	select {
	case err := <-errChan:
		require.Error(t, err)
		require.ErrorContains(t, err, "accepting stream failed")
	case <-time.After(time.Second):
		t.Fatal("server didn't shut down")
	}
}

func TestHTTPContextFromQUIC(t *testing.T) {
	conn := newUPDConnLocalhost(t)
	tr := &quic.Transport{
		Conn: conn,
		ConnContext: func(ctx context.Context) context.Context {
			return context.WithValue(ctx, "foo", "bar") //nolint:staticcheck
		},
	}
	defer tr.Close()
	tlsConf := getTLSConfig()
	tlsConf.NextProtos = []string{http3.NextProtoH3}
	ln, err := tr.Listen(tlsConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	mux := http.NewServeMux()
	ctxChan := make(chan context.Context, 1)
	mux.HandleFunc("/quic-conn-context", func(w http.ResponseWriter, r *http.Request) {
		ctxChan <- r.Context()
	})

	server := &http3.Server{Handler: mux}
	go func() {
		c, err := ln.Accept(context.Background())
		require.NoError(t, err)
		server.ServeQUICConn(c)
	}()

	cl := newHTTP3Client(t)
	resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/quic-conn-context", conn.LocalAddr().(*net.UDPAddr).Port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case ctx := <-ctxChan:
		v, ok := ctx.Value("foo").(string)
		require.True(t, ok)
		require.Equal(t, "bar", v)
	default:
		t.Fatal("context not set")
	}
}

func TestHTTPConnContext(t *testing.T) {
	mux := http.NewServeMux()
	requestCtxChan := make(chan context.Context, 1)
	mux.HandleFunc("/context", func(w http.ResponseWriter, r *http.Request) {
		requestCtxChan <- r.Context()
	})

	var server *http3.Server
	connCtxChan := make(chan context.Context, 1)
	port := startHTTPServer(t,
		mux,
		func(s *http3.Server) { server = s },
		func(s *http3.Server) {
			s.ConnContext = func(ctx context.Context, c quic.Connection) context.Context {
				connCtxChan <- ctx
				ctx = context.WithValue(ctx, "foo", "bar") //nolint:staticcheck
				return ctx
			}
		},
	)

	resp, err := newHTTP3Client(t).Get(fmt.Sprintf("https://localhost:%d/context", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tracingID quic.ConnectionTracingID
	select {
	case ctx := <-connCtxChan:
		serv, ok := ctx.Value(http3.ServerContextKey).(*http3.Server)
		require.True(t, ok)
		require.Equal(t, server, serv)

		id, ok := ctx.Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
		require.True(t, ok)
		tracingID = id
	default:
		t.Fatal("handler was not called")
	}

	select {
	case ctx := <-requestCtxChan:
		v, ok := ctx.Value("foo").(string)
		require.True(t, ok)
		require.Equal(t, "bar", v)

		serv, ok := ctx.Value(http3.ServerContextKey).(*http3.Server)
		require.True(t, ok)
		require.Equal(t, server, serv)

		id, ok := ctx.Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
		require.True(t, ok)
		require.Equal(t, tracingID, id)
	default:
		t.Fatal("handler was not called")
	}
}

func TestHTTPRemoteAddrContextKey(t *testing.T) {
	ctxChan := make(chan context.Context, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/remote-addr", func(w http.ResponseWriter, r *http.Request) {
		ctxChan <- r.Context()
	})

	port := startHTTPServer(t, mux)

	resp, err := newHTTP3Client(t).Get(fmt.Sprintf("https://localhost:%d/remote-addr", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case ctx := <-ctxChan:
		_, ok := ctx.Value(http3.RemoteAddrContextKey).(net.Addr)
		require.True(t, ok)
		require.Equal(t, "127.0.0.1", ctx.Value(http3.RemoteAddrContextKey).(*net.UDPAddr).IP.String())
	default:
		t.Fatal("handler was not called")
	}
}

func TestHTTPStreamedRequests(t *testing.T) {
	errChan := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/echoline", func(w http.ResponseWriter, r *http.Request) {
		defer close(errChan)
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		reader := bufio.NewReader(r.Body)
		for {
			msg, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if _, err := w.Write([]byte(msg)); err != nil {
				errChan <- err
				return
			}
			w.(http.Flusher).Flush()
		}
	})

	port := startHTTPServer(t, mux)

	r, w := io.Pipe()
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("https://localhost:%d/echoline", port), r)
	require.NoError(t, err)
	client := newHTTP3Client(t)
	rsp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, 200, rsp.StatusCode)

	reader := bufio.NewReader(rsp.Body)
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("Hello world, %d!\n", i)
		fmt.Fprint(w, msg)
		msgRcvd, err := reader.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, msg, msgRcvd)
	}
	require.NoError(t, req.Body.Close())

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("handler did not complete")
	}
}

func TestHTTP1xxResponse(t *testing.T) {
	header1 := "</style.css>; rel=preload; as=style"
	header2 := "</script.js>; rel=preload; as=script"
	data := "1xx-test-data"
	mux := http.NewServeMux()
	mux.HandleFunc("/103-early-data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", header1)
		w.Header().Add("Link", header2)
		w.WriteHeader(http.StatusEarlyHints)
		w.Write([]byte(data))
		w.WriteHeader(http.StatusOK)
	})

	port := startHTTPServer(t, mux)

	var (
		cnt    int
		status int
		hdr    textproto.MIMEHeader
	)
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			hdr = header
			status = code
			cnt++
			return nil
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/103-early-data", port), nil)
	require.NoError(t, err)
	resp, err := newHTTP3Client(t).Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, data, string(body))
	require.Equal(t, http.StatusEarlyHints, status)
	require.Equal(t, []string{header1, header2}, hdr.Values("Link"))
	require.Equal(t, 1, cnt)
	require.Equal(t, []string{header1, header2}, resp.Header.Values("Link"))
	require.NoError(t, resp.Body.Close())
}

func TestHTTP1xxTerminalResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/101-switch-protocols", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("foo", "bar")
		w.WriteHeader(http.StatusSwitchingProtocols)
	})

	port := startHTTPServer(t, mux)

	var (
		cnt    int
		status int
	)
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			status = code
			cnt++
			return nil
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/101-switch-protocols", port), nil)
	require.NoError(t, err)
	resp, err := newHTTP3Client(t).Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	require.Equal(t, "bar", resp.Header.Get("Foo"))
	require.Zero(t, status)
	require.Zero(t, cnt)
	require.NoError(t, resp.Body.Close())
}

func TestHTTP0RTT(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/0rtt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strconv.FormatBool(!r.TLS.HandshakeComplete)))
	})
	port := startHTTPServer(t, mux)

	var num0RTTPackets atomic.Uint32
	proxy := quicproxy.Proxy{
		Conn:       newUPDConnLocalhost(t),
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
		DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
			if contains0RTTPacket(data) {
				num0RTTPackets.Add(1)
			}
			return scaleDuration(25 * time.Millisecond)
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	tlsConf := getTLSClientConfigWithoutServerName()
	puts := make(chan string, 10)
	tlsConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(10), nil, puts)
	tr := &http3.Transport{
		TLSClientConfig:    tlsConf,
		QUICConfig:         getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
		DisableCompression: true,
	}
	defer tr.Close()

	proxyPort := proxy.LocalAddr().(*net.UDPAddr).Port
	req, err := http.NewRequest(http3.MethodGet0RTT, fmt.Sprintf("https://localhost:%d/0rtt", proxyPort), nil)
	require.NoError(t, err)
	rsp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, 200, rsp.StatusCode)
	data, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, "false", string(data))
	require.Zero(t, num0RTTPackets.Load())

	select {
	case <-puts:
	case <-time.After(time.Second):
		t.Fatal("did not receive session ticket")
	}

	tr2 := &http3.Transport{
		TLSClientConfig:    tr.TLSClientConfig,
		QUICConfig:         tr.QUICConfig,
		DisableCompression: true,
	}
	defer tr2.Close()
	rsp, err = tr2.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, 200, rsp.StatusCode)
	data, err = io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, "true", string(data))
	require.NotZero(t, num0RTTPackets.Load())
}

func TestHTTPStreamer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/httpstreamer", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		str := w.(http3.HTTPStreamer).HTTPStream()
		str.Write([]byte("foobar"))

		// Do this in a Go routine, so that the handler returns early.
		// This way, we can also check that the HTTP/3 doesn't close the stream.
		go func() {
			defer str.Close()
			_, _ = io.Copy(str, str)
		}()
	})

	port := startHTTPServer(t, mux)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d/httpstreamer", port), nil)
	require.NoError(t, err)
	tlsConf := getTLSClientConfigWithoutServerName()
	tlsConf.NextProtos = []string{http3.NextProtoH3}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := quic.Dial(ctx, newUPDConnLocalhost(t), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, tlsConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	tr := http3.Transport{}
	cc := tr.NewClientConn(conn)
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	require.NoError(t, str.SendRequestHeader(req))

	rsp, err := str.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, 200, rsp.StatusCode)

	b := make([]byte, 6)
	_, err = io.ReadFull(str, b)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), b)

	_, err = str.Write(PRData)
	require.NoError(t, err)
	require.NoError(t, str.Close())
	repl, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRData, repl)
}
