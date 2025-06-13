package self_test

import (
	"context"
	"fmt"
	"github.com/Noooste/fhttp"
	"github.com/Noooste/utls"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/Noooste/uquic-go"
	"github.com/Noooste/uquic-go/http3"
	quicproxy "github.com/Noooste/uquic-go/integrationtests/tools/proxy"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPShutdown(t *testing.T) {
	mux := http.NewServeMux()
	var server *http3.Server
	port := startHTTPServer(t, mux, func(s *http3.Server) { server = s })
	client := newHTTP3Client(t)

	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		go func() {
			require.NoError(t, server.Close())
		}()
		time.Sleep(scaleDuration(10 * time.Millisecond)) // make sure the server started shutting down
	})

	_, err := client.Get(fmt.Sprintf("https://localhost:%d/shutdown", port))
	require.Error(t, err)
	var appErr *http3.Error
	require.ErrorAs(t, err, &appErr)
	require.Equal(t, http3.ErrCodeNoError, appErr.ErrorCode)
}

func TestGracefulShutdownShortRequest(t *testing.T) {
	var server *http3.Server
	mux := http.NewServeMux()
	port := startHTTPServer(t, mux, func(s *http3.Server) { server = s })
	errChan := make(chan error, 1)
	proceed := make(chan struct{})
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		go func() {
			defer close(errChan)
			errChan <- server.Shutdown(context.Background())
		}()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-proceed
		w.Write([]byte("shutdown"))
	})

	connChan := make(chan quic.EarlyConnection, 1)
	tr := &http3.Transport{
		TLSClientConfig: getTLSClientConfigWithoutServerName(),
		Dial: func(ctx context.Context, a string, tlsConf *tls.Config, conf *quic.Config) (quic.EarlyConnection, error) {
			addr, err := net.ResolveUDPAddr("udp", a)
			if err != nil {
				return nil, err
			}
			conn, err := quic.DialEarly(ctx, newUDPConnLocalhost(t), addr, tlsConf, conf)
			connChan <- conn
			return conn, err
		},
	}
	t.Cleanup(func() { tr.Close() })

	client := &http.Client{Transport: tr}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/shutdown", port), nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var conn quic.EarlyConnection
	select {
	case conn = <-connChan:
	default:
		t.Fatal("expected a connection")
	}

	type result struct {
		body []byte
		err  error
	}
	resultChan := make(chan result, 1)
	go func() {
		body, err := io.ReadAll(resp.Body)
		resultChan <- result{body: body, err: err}
	}()
	select {
	case <-resultChan:
		t.Fatal("request body shouldn't have been read yet")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	select {
	case <-conn.Context().Done():
		t.Fatal("connection shouldn't have been closed")
	default:
	}

	// allow the request to proceed
	close(proceed)
	select {
	case res := <-resultChan:
		require.NoError(t, res.err)
		require.Equal(t, []byte("shutdown"), res.body)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// now that the stream count dropped to 0, the client should close the connection
	select {
	case <-conn.Context().Done():
		var appErr *quic.ApplicationError
		require.ErrorAs(t, context.Cause(conn.Context()), &appErr)
		assert.False(t, appErr.Remote)
		assert.Equal(t, quic.ApplicationErrorCode(http3.ErrCodeNoError), appErr.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not complete")
	}
}

func TestGracefulShutdownIdleConnection(t *testing.T) {
	var server *http3.Server
	port := startHTTPServer(t, http.NewServeMux(), func(s *http3.Server) { server = s })

	connChan := make(chan quic.EarlyConnection, 1)
	tr := &http3.Transport{
		TLSClientConfig: getTLSClientConfigWithoutServerName(),
		Dial: func(ctx context.Context, a string, tlsConf *tls.Config, conf *quic.Config) (quic.EarlyConnection, error) {
			addr, err := net.ResolveUDPAddr("udp", a)
			if err != nil {
				return nil, err
			}
			conn, err := quic.DialEarly(ctx, newUDPConnLocalhost(t), addr, tlsConf, conf)
			connChan <- conn
			return conn, err
		},
	}
	t.Cleanup(func() { tr.Close() })

	client := &http.Client{Transport: tr}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/", port), nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	require.NoError(t, resp.Body.Close())

	var conn quic.EarlyConnection
	select {
	case conn = <-connChan:
	default:
		t.Fatal("expected a connection")
	}
	// the connection should still be alive (and idle)
	select {
	case <-conn.Context().Done():
		t.Fatal("connection shouldn't have been closed")
	default:
	}

	shutdownChan := make(chan error, 1)
	go func() { shutdownChan <- server.Shutdown(context.Background()) }()

	// since the connection is idle, the client should close it immediately
	select {
	case <-conn.Context().Done():
		var appErr *quic.ApplicationError
		require.ErrorAs(t, context.Cause(conn.Context()), &appErr)
		assert.False(t, appErr.Remote)
		assert.Equal(t, quic.ApplicationErrorCode(http3.ErrCodeNoError), appErr.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestGracefulShutdownLongLivedRequest(t *testing.T) {
	delay := scaleDuration(25 * time.Millisecond)
	errChan := make(chan error, 1)
	requestChan := make(chan time.Duration, 1)

	var server *http3.Server
	mux := http.NewServeMux()
	port := startHTTPServer(t, mux, func(s *http3.Server) { server = s })
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		// The request simulated here takes longer than the server's graceful shutdown period.
		// We expect it to be terminated once the server shuts down.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), delay)
			defer cancel()
			errChan <- server.Shutdown(ctx)
		}()

		// measure how long it takes until the request errors
		for t := range time.NewTicker(delay / 10).C {
			if _, err := w.Write([]byte(t.String())); err != nil {
				requestChan <- time.Since(start)
				return
			}
		}
	})

	start := time.Now()
	resp, err := newHTTP3Client(t).Get(fmt.Sprintf("https://localhost:%d/shutdown", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = io.Copy(io.Discard, resp.Body)
	require.Error(t, err)
	var h3Err *http3.Error
	require.ErrorAs(t, err, &h3Err)
	require.Equal(t, http3.ErrCodeNoError, h3Err.ErrorCode)
	took := time.Since(start)
	require.InDelta(t, delay.Seconds(), took.Seconds(), (delay / 2).Seconds())

	// make sure that shutdown returned due to context deadline
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not return due to context deadline")
	}

	select {
	case requestDuration := <-requestChan:
		require.InDelta(t, delay.Seconds(), requestDuration.Seconds(), (delay / 2).Seconds())
	case <-time.After(time.Second):
		t.Fatal("did not receive request duration")
	}
}

func TestGracefulShutdownPendingStreams(t *testing.T) {
	rtt := scaleDuration(25 * time.Millisecond)

	handlerChan := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/helloworld", func(w http.ResponseWriter, r *http.Request) {
		handlerChan <- struct{}{}
		time.Sleep(rtt)
		w.Write([]byte("hello world"))
	})
	var server *http3.Server
	port := startHTTPServer(t, mux, func(s *http3.Server) { server = s })
	connChan := make(chan quic.EarlyConnection, 1)
	tr := &http3.Transport{
		TLSClientConfig: getTLSClientConfigWithoutServerName(),
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			conn, err := quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
			connChan <- conn
			return conn, err
		},
	}
	cl := &http.Client{Transport: tr}

	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
		DelayPacket: func(_ quicproxy.Direction, _, _ net.Addr, data []byte) time.Duration {
			return rtt
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	proxyPort := proxy.LocalAddr().(*net.UDPAddr).Port

	errChan := make(chan error, 1)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d/helloworld", proxyPort), nil)
	require.NoError(t, err)
	go func() {
		resp, err := cl.Do(req)
		if err != nil {
			errChan <- err
			return
		}
		if resp.StatusCode != http.StatusOK {
			errChan <- fmt.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
		}
	}()

	select {
	case <-handlerChan:
	case <-time.After(time.Second):
		t.Fatal("did not receive request")
	}

	shutdownChan := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { shutdownChan <- server.Shutdown(ctx) }()
	time.Sleep(rtt / 2) // wait for the server to start shutting down

	var conn quic.EarlyConnection
	select {
	case conn = <-connChan:
	case <-time.After(time.Second):
		t.Fatal("connection was not opened")
	}

	// make sure that the server rejects further requests
	for range 3 {
		str, err := conn.OpenStreamSync(ctx)
		require.NoError(t, err)
		str.Write([]byte("foobar"))
		select {
		case <-str.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("stream was not rejected")
		}
		_, err = str.Read(make([]byte, 10))
		var serr *quic.StreamError
		require.ErrorAs(t, err, &serr)
		require.Equal(t, quic.StreamErrorCode(http3.ErrCodeRequestRejected), serr.ErrorCode)
	}

	cancel()
	select {
	case err := <-shutdownChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not complete")
	}
}

func TestHTTP3ListenerClosing(t *testing.T) {
	t.Run("application listener", func(t *testing.T) {
		testHTTP3ListenerClosing(t, false, true)
	})
	t.Run("listener created by the http3.Server", func(t *testing.T) {
		testHTTP3ListenerClosing(t, false, false)
	})
}

func TestHTTP3ListenerGracefulShutdown(t *testing.T) {
	t.Run("application listener", func(t *testing.T) {
		testHTTP3ListenerClosing(t, true, true)
	})
	t.Run("listener created by the http3.Server", func(t *testing.T) {
		testHTTP3ListenerClosing(t, true, false)
	})
}

func testHTTP3ListenerClosing(t *testing.T, graceful, useApplicationListener bool) {
	dial := func(t *testing.T, ctx context.Context, u *url.URL) error {
		t.Helper()
		tlsConf := getTLSClientConfig()
		tlsConf.NextProtos = []string{http3.NextProtoH3}
		tr := &http3.Transport{TLSClientConfig: tlsConf}
		defer tr.Close()
		cl := &http.Client{Transport: tr}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		require.NoError(t, err)
		resp, err := cl.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handlerChan := make(chan struct{})
	mux.HandleFunc("/long", func(w http.ResponseWriter, r *http.Request) {
		<-handlerChan
		w.WriteHeader(http.StatusOK)
	})

	tlsConf := http3.ConfigureTLSConfig(getTLSConfig())
	server := &http3.Server{
		Handler: mux,
		// the following values will be ignored when using ServeListener
		TLSConfig:  tlsConf,
		QUICConfig: getQuicConfig(nil),
		Addr:       "127.0.0.1:47283",
	}

	serveChan := make(chan error, 1)
	var host string
	var ln *quic.EarlyListener // only set when using application listener
	if useApplicationListener {
		var err error
		ln, err = quic.ListenEarly(newUDPConnLocalhost(t), tlsConf, getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()
		host = ln.Addr().String()
		go func() { serveChan <- server.ServeListener(ln) }()
	} else {
		go func() { serveChan <- server.ListenAndServe() }()
		host = server.Addr
	}

	u := &url.URL{Scheme: "https", Host: host, Path: "/ok"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, dial(t, ctx, u))

	longReqChan := make(chan error, 1)
	shutdownChan := make(chan error, 1)
	if graceful {
		go func() {
			u := &url.URL{Scheme: "https", Host: host, Path: "/long"}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			longReqChan <- dial(t, ctx, u)
		}()
		time.Sleep(scaleDuration(10 * time.Millisecond))

		go func() { shutdownChan <- server.Shutdown(context.Background()) }()
	} else {
		require.NoError(t, server.Close())
	}

	select {
	case err := <-serveChan:
		require.ErrorIs(t, err, http.ErrServerClosed)
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}

	// If the listener was created by the http3.Server, it will now be closed.
	if !useApplicationListener {
		ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(10*time.Millisecond))
		defer cancel()
		require.ErrorIs(t, dial(t, ctx, u), context.DeadlineExceeded)
	} else {
		// If the listener was created by the application, it will not be closed,
		// and it can be used to accept new connections.
		errChan := make(chan error, 1)
		go func() {
			for {
				conn, err := ln.Accept(context.Background())
				if err != nil {
					errChan <- err
					return
				}
				select {
				case <-conn.HandshakeComplete():
					conn.CloseWithError(1337, "")
				case <-time.After(time.Second):
					errChan <- fmt.Errorf("connection did not complete handshake")
				}
				errChan <- nil
			}
		}()

		for range 2 {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := dial(t, ctx, u)
			var h3Err *http3.Error
			require.ErrorAs(t, err, &h3Err)
			require.Equal(t, http3.ErrCode(1337), h3Err.ErrorCode)
			select {
			case err := <-errChan:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("server did not accept connection")
			}
		}
	}

	// the long request should have been terminated
	if graceful {
		select {
		case err := <-longReqChan:
			t.Fatalf("request should not have terminated: %v", err)
		case err := <-shutdownChan:
			t.Fatalf("graceful shutdown should not have returned: %v", err)
		case <-time.After(scaleDuration(10 * time.Millisecond)):
		}

		close(handlerChan)
		select {
		case err := <-longReqChan:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("long request did not terminate")
		}

		select {
		case err := <-shutdownChan:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("shutdown did not complete")
		}
	}
}
