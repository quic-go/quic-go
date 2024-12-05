package self_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

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
		time.Sleep(50 * time.Millisecond) // make sure the server started shutting down
	})

	_, err := client.Get(fmt.Sprintf("https://localhost:%d/shutdown", port))
	require.Error(t, err)
	var appErr *http3.Error
	require.ErrorAs(t, err, &appErr)
	require.Equal(t, http3.ErrCodeNoError, appErr.ErrorCode)
}

func TestGracefulShutdownShortRequest(t *testing.T) {
	delay := scaleDuration(50 * time.Millisecond)

	var server *http3.Server
	mux := http.NewServeMux()
	port := startHTTPServer(t, mux, func(s *http3.Server) { server = s })
	errChan := make(chan error, 1)
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		go func() {
			defer close(errChan)
			errChan <- server.Shutdown(context.Background())
		}()
		time.Sleep(delay)
		w.Write([]byte("shutdown"))
	})

	client := newHTTP3Client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*delay)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/shutdown", port), nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, []byte("shutdown"), body)
	client.Transport.(*http3.Transport).Close() // manually close the client

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not complete")
	}
}

func TestGracefulShutdownLongLivedRequest(t *testing.T) {
	delay := scaleDuration(50 * time.Millisecond)
	errChan := make(chan error, 1)
	requestChan := make(chan time.Duration, 1)

	var server *http3.Server
	mux := http.NewServeMux()
	port := startHTTPServer(t, mux, func(s *http3.Server) { server = s })
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

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
